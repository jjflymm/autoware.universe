#include "lidar_localizer/lidar_localizer.hpp"
// 构造函数
lidar_localizer::lidar_localizer(std::string node_name, const rclcpp::NodeOptions &options) : rclcpp::Node(node_name, options),
                                                                                              tf_buffer(this->get_clock()),
                                                                                              tf_listener(tf_buffer),
                                                                                              tf_broadcaster(*this)
{
    /***********************hyper parameters********************************/
    this->declare_parameter("imu_compensation_time", -0.000414348); // imu时间补偿
    this->get_parameter("imu_compensation_time", imu_compensation_time);

    this->declare_parameter("lidar_compensation_time", 0.0308697); // lidar时间补偿
    this->get_parameter("lidar_compensation_time", lidar_compensation_time);

    this->declare_parameter("map_path", "map"); // 点云地图路劲
    this->get_parameter("map_path", map_path);

    this->declare_parameter("lidar_min_depth_range", 0.2); // lidar数据最小深度范围
    this->get_parameter("lidar_min_depth_range", lidar_min_depth_range);

    this->declare_parameter("lidar_max_depth_range", 150.0); // lidar数据最大深度范围
    this->get_parameter("lidar_max_depth_range", lidar_max_depth_range);

    this->declare_parameter("sub_gnss_pose_topic", "/location/gnss/pose"); // gnss定位话题，通过gnss得到的base在world系下的位置
    this->get_parameter("sub_gnss_pose_topic", sub_gnss_pose_topic);

    this->declare_parameter("sub_lidar_topic", "/sensor/lidar/top"); // 顶部激光雷达话题
    this->get_parameter("sub_lidar_topic", sub_lidar_topic);

    this->declare_parameter("sub_imu_topic", "/sensor/imu"); // imu话题
    this->get_parameter("sub_imu_topic", sub_imu_topic);

    this->declare_parameter("pub_lidar_pose_topic", "/location/lidar/pose"); // lidar在world系中的位姿
    this->get_parameter("pub_lidar_pose_topic", pub_lidar_pose_topic);

    this->declare_parameter("imu_coor_sys", "imu_link"); // imu坐标系
    this->get_parameter("imu_coor_sys", imu_coor_sys);

    this->declare_parameter("lidar_coor_sys", "top_lidar_link"); // lidar坐标系
    this->get_parameter("lidar_coor_sys", lidar_coor_sys);

    this->declare_parameter("gnss_coor_sys", "gnss_link"); // lidar坐标系
    this->get_parameter("gnss_coor_sys", gnss_coor_sys);

    this->declare_parameter("world_coor_sys", "map"); // base坐标系
    this->get_parameter("world_coor_sys", world_coor_sys);

    this->declare_parameter("NUM_MAX_ITERATIONS", 4); // 卡尔曼滤波的最大迭代次数
    this->get_parameter("NUM_MAX_ITERATIONS", NUM_MAX_ITERATIONS);

    /**************imu****************/
    this->declare_parameter("gyr_cov", 0.1); // imu陀螺仪的协方差
    this->get_parameter("gyr_cov", gyr_cov);

    this->declare_parameter("acc_cov", 0.1); // imu加速度计的协方差
    this->get_parameter("acc_cov", acc_cov);

    this->declare_parameter("b_gyr_cov", 0.0001); // imu陀螺仪的偏置的协方差
    this->get_parameter("b_gyr_cov", b_gyr_cov);

    this->declare_parameter("b_acc_cov", 0.0001); // imu加速度计偏置的协方差
    this->get_parameter("b_acc_cov", b_acc_cov);
    /*************************vgicp parameters****************************/
    this->declare_parameter("vgicp_resolution", 2.0); // 体素大小
    this->get_parameter("vgicp_resolution", vgicp_resolution);
    this->declare_parameter("vgicp_num_threads", 8); // 线程数
    this->get_parameter("vgicp_num_threads", vgicp_num_threads);
    /************************pose covariance******************************/
    std::vector<double> pose_covariance_tmp = this->declare_parameter<std::vector<double>>("pose_covariance");
    for (std::size_t i = 0; i < pose_covariance_tmp.size(); ++i)
        pose_covariance[i] = pose_covariance_tmp[i];
    /*********************************************************************************/
    pose_status = UNINITIALIZE;

    undistort_pcl_ds.reset(new PointCloud_XYZI()); // 下采样去畸变激光雷达点云

    p_imu = std::make_shared<ImuProcess>(); // IMU数据预处理类
    /**************************************ivox****************************************/
#ifdef USE_IVOX
    ivox_options.resolution_ = 1.0;
    ivox_options.nearby_type_ = IVoxType::NearbyType::NEARBY18;
    p_ivox = std::make_shared<IVoxType>(ivox_options);
    FIRST_BUILD_INCREMENTAL_MAP = true;
#endif
    /*******************************获得传感器的变换关系****************************/
    // lidar to imu
    if (!get_tf(imu_coor_sys, lidar_coor_sys, tf_i_l))
        return;
    // lidar to gnss
    if (!get_tf(gnss_coor_sys, lidar_coor_sys, tf_g_l))
        return;

    // 设置IMU的参数，对p_imu进行初始化，其中p_imu为ImuProcess的智能指针（ImuProcess是进行IMU处理的类）
    tf2::Quaternion tf2_quat;
    tf2::convert(tf_i_l.transform.rotation, tf2_quat);
    tf2::Matrix3x3 matrix_3x3(tf2_quat);

    Lidar_T_wrt_IMU << tf_i_l.transform.translation.x, tf_i_l.transform.translation.y, tf_i_l.transform.translation.z;
    Lidar_R_wrt_IMU << matrix_3x3[0][0], matrix_3x3[0][1], matrix_3x3[0][2],
        matrix_3x3[1][0], matrix_3x3[1][1], matrix_3x3[1][2],
        matrix_3x3[2][0], matrix_3x3[2][1], matrix_3x3[2][2];

    p_imu->set_extrinsic(Lidar_T_wrt_IMU, Lidar_R_wrt_IMU);
    p_imu->set_gyr_cov(V3D(gyr_cov, gyr_cov, gyr_cov));
    p_imu->set_acc_cov(V3D(acc_cov, acc_cov, acc_cov));
    p_imu->set_gyr_bias_cov(V3D(b_gyr_cov, b_gyr_cov, b_gyr_cov));
    p_imu->set_acc_bias_cov(V3D(b_acc_cov, b_acc_cov, b_acc_cov));

    double epsi[23] = {0.001};
    std::fill(epsi, epsi + 23, 0.001); // 从epsi填充到epsi+22 也就是全部数组置0.001
    // 将函数地址传入kf对象中，用于接收特定于系统的模型及其差异
    // 作为一个维数变化的特征矩阵进行测量。
    // 通过一个函数（h_dyn_share_in）同时计算测量（z）、估计测量（h）、偏微分矩阵（h_x，h_v）和噪声协方差（R）。
    eskf.init_dyn_share(get_f, df_dx, df_dw, std::bind(&lidar_localizer::h_share_model, this, std::placeholders::_1, std::placeholders::_2), NUM_MAX_ITERATIONS, epsi);

#ifdef USE_VGICP_CUDA
    registration_ptr.reset(new fast_gicp::FastVGICPCuda<PointSource, PointTarget>());
    registration_ptr->setResolution(vgicp_resolution);
    registration_ptr->setCorrespondenceRandomness(20);
    registration_ptr->setRegularizationMethod(fast_gicp::RegularizationMethod::PLANE);
    registration_ptr->setNearestNeighborSearchMethod(fast_gicp::NearestNeighborMethod::CPU_PARALLEL_KDTREE);
#else
    registration_ptr.reset(new fast_gicp::FastVGICP<PointSource, PointTarget>());
    registration_ptr->setResolution(vgicp_resolution);
    registration_ptr->setNumThreads(vgicp_num_threads);
    registration_ptr->setNeighborSearchMethod(fast_gicp::NeighborSearchMethod::DIRECT7);
    registration_ptr->setVoxelAccumulationMode(fast_gicp::VoxelAccumulationMode::ADDITIVE_WEIGHTED);
#endif

    sub_pcl = this->create_subscription<sensor_msgs::msg::PointCloud2>(sub_lidar_topic, rclcpp::SensorDataQoS().keep_last(1),
                                                                       std::bind(&lidar_localizer::pcl_callback, this, std::placeholders::_1));
    sub_imu = this->create_subscription<sensor_msgs::msg::Imu>(sub_imu_topic, 2000,
                                                               std::bind(&lidar_localizer::imu_callback, this, std::placeholders::_1));
    sub_gnss_pose = this->create_subscription<geometry_msgs::msg::PoseWithCovarianceStamped>(sub_gnss_pose_topic, 1,
                                                                                             std::bind(&lidar_localizer::gnss_pose_callback,
                                                                                                       this, std::placeholders::_1));
    pub_lidar_pose = this->create_publisher<geometry_msgs::msg::PoseWithCovarianceStamped>(pub_lidar_pose_topic, 1);
    // test
    pub_cloud = this->create_publisher<sensor_msgs::msg::PointCloud2>("location_cloud", 1);
    pub_lidar = this->create_publisher<sensor_msgs::msg::PointCloud2>("lidar_cloud", 1);
    pub_local_map = this->create_publisher<sensor_msgs::msg::PointCloud2>("location_local_map_cloud", 1);

    key_3dPoses.reset(new PointCloud_XYZ());

    load_key_pose_file();
}
// lidar回调
void lidar_localizer::pcl_callback(const sensor_msgs::msg::PointCloud2 &_pcl_msg)
{
    PointCloud_XYZIT::Ptr pcl_filtered(new PointCloud_XYZIT());
    PointCloud_XYZ::Ptr pcl_loop(new PointCloud_XYZ());
    // 检查点云时间戳的一致性，是否存在跳变
    static rclcpp::Time last_lidar_timestamp = rclcpp::Time(0);
    curr_lidar_timestamp = rclcpp::Time(_pcl_msg.header.stamp.sec * 1e9 + _pcl_msg.header.stamp.nanosec + lidar_compensation_time * 1e9);
    if (curr_lidar_timestamp <= last_lidar_timestamp)
    {
        RCLCPP_ERROR(this->get_logger(), "lidar loop back, clear buffer");
        lidar_buffer.clear();
        return;
    }
    last_lidar_timestamp = curr_lidar_timestamp;
    /**********************激光雷达数据预处理********************/
    pcl::PointCloud<LidarPoint> pcl_org; // 原始点云
    sensor_msgs::msg::PointCloud2 correct_pcl_msg = _pcl_msg;
    correct_pcl_msg.header.stamp = curr_lidar_timestamp;
    pcl::fromROSMsg(correct_pcl_msg, pcl_org); // ros点云转pcl点云
    for (size_t i = 0; i < pcl_org.points.size(); i++)
    {
        // 降采样
        if (i % 2 == 0)
            continue;
        // 点的深度信息
        double range = pow(pcl_org.points[i].x, 2.0) + pow(pcl_org.points[i].y, 2.0) + pow(pcl_org.points[i].z, 2.0);
        // 点过滤
        if (range < (lidar_min_depth_range * lidar_min_depth_range) || range > (lidar_max_depth_range * lidar_max_depth_range))
            continue;
        Point_XYZIT pt_xyzit;
        pt_xyzit.x = pcl_org.points[i].x;
        pt_xyzit.y = pcl_org.points[i].y;
        pt_xyzit.z = pcl_org.points[i].z;

        pt_xyzit.intensity = pcl_org.points[i].intensity;

        pt_xyzit.time = pcl_org.points[i].time_stamp + lidar_compensation_time; // time unit: s

        pcl_filtered->points.push_back(pt_xyzit);
    }
    mtx_buffer.lock();
    if (lidar_buffer.size() == 2)
        lidar_buffer.pop_front();
    lidar_buffer.push_back(pcl_filtered);
    mtx_buffer.unlock();
    sig_buffer.notify_all();
    // 循环队列，用于回环检测投票
    pcl::copyPointCloud(*pcl_filtered, *pcl_loop);
    mtx_buffer.lock();
    if (lidar_loop_buffer.size() == 2)
        lidar_loop_buffer.pop_front();
    lidar_loop_buffer.push_back(pcl_loop);
    mtx_buffer.unlock();
    sig_buffer.notify_all();
}
// imu回调
void lidar_localizer::imu_callback(const sensor_msgs::msg::Imu &_imu_msg)
{
    mtx_buffer.lock();
    static rclcpp::Time last_imu_timestamp = rclcpp::Time(0);
    rclcpp::Time curr_imu_timestamp = rclcpp::Time(_imu_msg.header.stamp.sec * 1e9 + _imu_msg.header.stamp.nanosec + imu_compensation_time * 1e9);

    if (curr_imu_timestamp <= last_imu_timestamp) // 检测IMU时间一致性，是否存在跳变
    {
        RCLCPP_WARN(this->get_logger(), "imu loop back, clear buffer");
        imu_buffer.clear();
        mtx_buffer.unlock();
        return;
    }
    last_imu_timestamp = curr_imu_timestamp;
    sensor_msgs::msg::Imu correct_imu_msg = _imu_msg;
    correct_imu_msg.header.stamp = curr_imu_timestamp;
    imu_buffer.push_back(correct_imu_msg);
    mtx_buffer.unlock();     // 解锁
    sig_buffer.notify_all(); // 唤醒阻塞的线程
}
// 数据同步,imu和lidar
bool lidar_localizer::data_synchronization(MeasureGroup &meas)
{
    if (lidar_buffer.empty() || imu_buffer.empty()) // 如果缓存队列中没有数据，则返回false
        return false;
    /*** push a lidar scan ***/
    mtx_buffer.lock();
    meas.lidar = lidar_buffer.front();
    lidar_buffer.pop_front();
    mtx_buffer.unlock();
    sig_buffer.notify_all(); // 唤醒阻塞的线程
    meas.lidar_beg_time = meas.lidar->points.front().time;
    meas.lidar_end_time = meas.lidar->points.back().time;
    double imu_front_time = imu_buffer.front().header.stamp.sec + imu_buffer.front().header.stamp.nanosec * 1e-9;
    double imu_back_time = imu_buffer.back().header.stamp.sec + imu_buffer.back().header.stamp.nanosec * 1e-9;

    // // imu和lidar时间是否同步
    // if (fabs(imu_back_time - meas.lidar_end_time)>0.1)
    //     return false;

    /*** push imu data, and pop from imu buffer ***/
    // 取出当前lidar帧，开始到结束时间段之间的imu数据
    meas.imu.clear();
    while ((!imu_buffer.empty()) && (imu_front_time < meas.lidar_end_time))
    {
        imu_front_time = imu_buffer.front().header.stamp.sec + imu_buffer.front().header.stamp.nanosec * 1e-9;
        if (imu_front_time > meas.lidar_end_time)
            break;
        mtx_buffer.lock();
        meas.imu.push_back(imu_buffer.front());
        imu_buffer.pop_front();
        mtx_buffer.unlock();
        sig_buffer.notify_all(); // 唤醒阻塞的线程
    }

    if (meas.imu.empty() || meas.lidar->points.size() == 0)
        return false;

    return true;
}
// gnss位姿回调
void lidar_localizer::gnss_pose_callback(const geometry_msgs::msg::PoseWithCovarianceStamped &_gnss_msg)
{
    mtx_buffer.lock();
    if (gnss_pose_buffer.size() == 2)
        gnss_pose_buffer.pop_front();
    gnss_pose_buffer.push_back(_gnss_msg);
    mtx_buffer.unlock();
    sig_buffer.notify_all();
}
// 点云变换
PointCloud_XYZI lidar_localizer::transformPointCloud(PointCloud_XYZI &cloudIn, Point_XYZRPY &transformIn)
{
    PointCloud_XYZI cloudOut;

    int cloudSize = cloudIn.size();
    cloudOut.resize(cloudSize);

    Eigen::Affine3f transCur = pcl::getTransformation(transformIn.x, transformIn.y, transformIn.z, transformIn.roll, transformIn.pitch, transformIn.yaw);

#pragma omp parallel for num_threads(6)
    for (int i = 0; i < cloudSize; ++i)
    {
        const auto &pointFrom = cloudIn.points[i];
        cloudOut.points[i].x = transCur(0, 0) * pointFrom.x + transCur(0, 1) * pointFrom.y + transCur(0, 2) * pointFrom.z + transCur(0, 3);
        cloudOut.points[i].y = transCur(1, 0) * pointFrom.x + transCur(1, 1) * pointFrom.y + transCur(1, 2) * pointFrom.z + transCur(1, 3);
        cloudOut.points[i].z = transCur(2, 0) * pointFrom.x + transCur(2, 1) * pointFrom.y + transCur(2, 2) * pointFrom.z + transCur(2, 3);
        cloudOut.points[i].intensity = pointFrom.intensity;
    }
    return cloudOut;
}
// 点云变换
PointCloud_XYZ lidar_localizer::transformPointCloud(PointCloud_XYZ &cloudIn, Point_XYZRPY &transformIn)
{
    PointCloud_XYZ cloudOut;

    int cloudSize = cloudIn.size();
    cloudOut.resize(cloudSize);

    Eigen::Affine3f transCur = pcl::getTransformation(transformIn.x, transformIn.y, transformIn.z, transformIn.roll, transformIn.pitch, transformIn.yaw);

#pragma omp parallel for num_threads(6)
    for (int i = 0; i < cloudSize; ++i)
    {
        const auto &pointFrom = cloudIn.points[i];
        cloudOut.points[i].x = transCur(0, 0) * pointFrom.x + transCur(0, 1) * pointFrom.y + transCur(0, 2) * pointFrom.z + transCur(0, 3);
        cloudOut.points[i].y = transCur(1, 0) * pointFrom.x + transCur(1, 1) * pointFrom.y + transCur(1, 2) * pointFrom.z + transCur(1, 3);
        cloudOut.points[i].z = transCur(2, 0) * pointFrom.x + transCur(2, 1) * pointFrom.y + transCur(2, 2) * pointFrom.z + transCur(2, 3);
    }
    return cloudOut;
}
// 回环检测
void lidar_localizer::loop_detection()
{
    LidarIris iris(4, 18, 1.6, 0.75, 50);
    std::map<int, LidarIris::FeatureDesc> key_iris_features;
    // key_iris_features.reserve(30);
    double tf_i_l_roll, tf_i_l_pitch, tf_i_l_yaw, tf_i_l_x, tf_i_l_y, tf_i_l_z;
    tf2::Quaternion tf2_quat;
    tf2::convert(tf_i_l.transform.rotation, tf2_quat);
    tf2::Matrix3x3 matrix_3x3(tf2_quat);
    matrix_3x3.getRPY(tf_i_l_roll, tf_i_l_pitch, tf_i_l_yaw);
    tf_i_l_x = tf_i_l.transform.translation.x;
    tf_i_l_y = tf_i_l.transform.translation.y;
    tf_i_l_z = tf_i_l.transform.translation.z;

    rclcpp::Publisher<sensor_msgs::msg::PointCloud2>::SharedPtr pub_loop_cloud = this->create_publisher<sensor_msgs::msg::PointCloud2>("loop_location_cloud", 1);
    rclcpp::Publisher<sensor_msgs::msg::PointCloud2>::SharedPtr pub_loop_local_map = this->create_publisher<sensor_msgs::msg::PointCloud2>("loop_local_map_cloud", 1);
    rclcpp::WallRate loop_rate(10); // 10hz
    while (rclcpp::ok())
    {
        if (pose_status >= INITIALIZED)
            return;

        // 通过GNSS加快回环速度和初始定位
        if (gnss_pose_buffer.size() > 0)
        {
            if (pose_status == UNINITIALIZE)
                pose_status = INITIALIZING;

            // KD_TREE<Point_XYZRPYI>::PointVector search_result;
            // vector<float> pointSearchSqDis(NEAREST_NUM);

            std::vector<float> search_dists;
            std::vector<int> search_idxes;

            std::vector<LidarIris::FeatureDesc> curr_lidar_iris_features;
            std::vector<std::pair<int, float>> idx_score_set;
            std::vector<int> select_search_idx_set;
            Point_XYZRPYI curr_infer_pose;
            Point_XYZ curr_infer_position;
            // 以gnss的位置当做猜测的初始位置
            mtx_buffer.lock();
            // 由gnss推测lidar在world系下的位置
            geometry_msgs::msg::Pose infer_pose = get_infer_position(tf_g_l, gnss_pose_buffer.back());
            curr_infer_position.x = infer_pose.position.x;
            curr_infer_position.y = infer_pose.position.y;
            curr_infer_position.z = infer_pose.position.z;
            mtx_buffer.unlock();
            sig_buffer.notify_all();
            // 得到当前lidar队列的iris特征
            mtx_buffer.lock();
            std::deque<PointCloud_XYZ::Ptr> lidar_loop_buffer_copy(lidar_loop_buffer);
            mtx_buffer.unlock();
            sig_buffer.notify_all();
            if (lidar_loop_buffer_copy.size() <= 0)
                continue;
            for (size_t i = 0; i < lidar_loop_buffer_copy.size(); i++)
            {
                PointCloud_XYZ::Ptr loop_pcl_ds(new PointCloud_XYZ());
                pcl::VoxelGrid<Point_XYZ> downSamplePointCloudFilter;
                downSamplePointCloudFilter.setLeafSize(0.1, 0.1, 0.1);
                downSamplePointCloudFilter.setInputCloud(lidar_loop_buffer_copy[i]);
                downSamplePointCloudFilter.filter(*loop_pcl_ds);
                // cv::Mat1b iris_feature = LidarIris::GetIris(*lidar_loop_buffer[i]);
                cv::Mat1b iris_feature = LidarIris::GetIris(*loop_pcl_ds);
                curr_lidar_iris_features.push_back(iris.GetFeature(iris_feature));
            }
            // ikdtree_pose.Radius_Search(curr_infer_pose, 5, search_result); // 在gnss坐标系下的方圆5m搜素关键位姿
            // ikdtree_pose.Nearest_Search(curr_infer_pose, NEAREST_NUM, search_result, pointSearchSqDis);
            kdtree_3dPose.nearestKSearch(curr_infer_position, NEAREST_NUM, search_idxes, search_dists);
            if (search_idxes.size() == 0)
                continue;
            for (size_t i = 0; i < search_idxes.size(); i++)
            {
                if (search_dists[i] > 10)
                    continue;
                int search_key_idx = search_idxes[i];
                select_search_idx_set.push_back(search_key_idx);
                if (key_iris_features.count(search_key_idx) == 0) // 若key_iris_features中不存在idx
                {
                    PointCloud_XYZI cloud_xyzi;
                    PointCloud_XYZ cloud_xyz;
                    if (pcl::io::loadPCDFile<pcl::PointXYZI>(map_path + "/" + std::to_string(search_key_idx) + ".pcd", cloud_xyzi) == -1) // 加载地图库中关键帧点云
                    {
                        RCLCPP_WARN(this->get_logger(), (std::string("unable to open ") + std::to_string(search_key_idx) + ".pcd").c_str());
                        continue;
                    }
                    pcl::copyPointCloud(cloud_xyzi, cloud_xyz);
                    cv::Mat1b iris_feature = LidarIris::GetIris(cloud_xyz);
                    key_iris_features[search_key_idx] = iris.GetFeature(iris_feature);

                    Point_XYZRPY pose;
                    pose.x = key_6dPoses.points[search_key_idx].x;
                    pose.y = key_6dPoses.points[search_key_idx].y;
                    pose.z = key_6dPoses.points[search_key_idx].z;
                    pose.roll = key_6dPoses.points[search_key_idx].roll;
                    pose.pitch = key_6dPoses.points[search_key_idx].pitch;
                    pose.yaw = key_6dPoses.points[search_key_idx].yaw;

                    local_key_frames[search_key_idx] = transformPointCloud(cloud_xyzi, pose);
                }
            }
            if(select_search_idx_set.size() == 0)
            {
                RCLCPP_WARN(this->get_logger(),"Unable to find keyframes within 10m range.loop may be fail.");
                continue;
            }
            // 删除在当前搜索半径范围内不存在的关键帧特征描述子
            for (auto iter = key_iris_features.begin(); iter != key_iris_features.end();)
            {
                if (std::find(select_search_idx_set.begin(), select_search_idx_set.end(), iter->first) == select_search_idx_set.end())
                    iter = key_iris_features.erase(iter);
                else
                    iter++;
            }
            // 删除在当前搜索半径范围内不存在的关键帧
            for (auto iter = local_key_frames.begin(); iter != local_key_frames.end();)
            {
                if (std::find(select_search_idx_set.begin(), select_search_idx_set.end(), iter->first) == select_search_idx_set.end())
                    iter = local_key_frames.erase(iter);
                else
                    iter++;
            }
            // 特征描述子比较
            for (size_t i = 0; i < curr_lidar_iris_features.size(); i++)
            {
                for (auto key_element : key_iris_features)
                {
                    int bias;
                    auto dist = iris.Compare(curr_lidar_iris_features[i], key_element.second, &bias);

                    idx_score_set.push_back(std::pair<int, float>(key_element.first, dist));
                }
            }
            std::sort(idx_score_set.begin(), idx_score_set.end(), [](std::pair<int, float> a, std::pair<int, float> b)
                      { return a.second < b.second; });
            // 建立局部点云地图
            PointCloud_XYZ::Ptr local_map(new PointCloud_XYZ());
            // local_map.reset(new PointCloud_XYZ());

            if (key_6dPoses.points[idx_score_set.front().first].idx == idx_score_set.front().first)
            {
                curr_infer_pose.x = key_6dPoses.points[idx_score_set.front().first].x;
                curr_infer_pose.y = key_6dPoses.points[idx_score_set.front().first].y;
                curr_infer_pose.z = key_6dPoses.points[idx_score_set.front().first].z;
                curr_infer_pose.roll = key_6dPoses.points[idx_score_set.front().first].roll;
                curr_infer_pose.pitch = key_6dPoses.points[idx_score_set.front().first].pitch;
                curr_infer_pose.yaw = key_6dPoses.points[idx_score_set.front().first].yaw;

                curr_infer_position.x = curr_infer_pose.x;
                curr_infer_position.y = curr_infer_pose.y;
                curr_infer_position.z = curr_infer_pose.z;
                // ikdtree_pose.Radius_Search(curr_infer_pose, 3, search_result); // 在gnss坐标系下的方圆15m搜素关键位姿
                search_idxes.clear();
                search_dists.clear();
                // ikdtree_pose.Nearest_Search(curr_infer_pose, NEAREST_NUM, search_result, pointSearchSqDis);
                kdtree_3dPose.nearestKSearch(curr_infer_position, NEAREST_NUM, search_idxes, search_dists);
                for (size_t i = 0; i < search_idxes.size(); i++)
                {
                    if (search_dists[i] > 10)
                        continue;
                    int search_key_idx = search_idxes[i];
                    if (local_key_frames.count(search_key_idx) == 0)
                    {
                        PointCloud_XYZI cloud_xyzi;

                        if (pcl::io::loadPCDFile<pcl::PointXYZI>(map_path + "/" + std::to_string(search_key_idx) + ".pcd", cloud_xyzi) == -1) // 加载地图库中关键帧点云
                        {
                            RCLCPP_WARN(this->get_logger(), (std::string("unable to open ") + std::to_string(search_key_idx) + ".pcd").c_str());
                            continue;
                        }

                        Point_XYZRPY pose;
                        pose.x = key_6dPoses.points[search_key_idx].x;
                        pose.y = key_6dPoses.points[search_key_idx].y;
                        pose.z = key_6dPoses.points[search_key_idx].z;
                        pose.roll = key_6dPoses.points[search_key_idx].roll;
                        pose.pitch = key_6dPoses.points[search_key_idx].pitch;
                        pose.yaw = key_6dPoses.points[search_key_idx].yaw;

                        local_key_frames[search_key_idx] = transformPointCloud(cloud_xyzi, pose);
                    }
                    // 构建初始的局部地图
                    PointCloud_XYZ cloud_xyz;
                    pcl::copyPointCloud(local_key_frames[search_key_idx], cloud_xyz);
                    *local_map += cloud_xyz;
                }
                // 发布局部地图
                sensor_msgs::msg::PointCloud2 local_map_cloud_msg;
                pcl::toROSMsg(*local_map, local_map_cloud_msg);
                local_map_cloud_msg.header.stamp = this->now();
                local_map_cloud_msg.header.frame_id = world_coor_sys;
                pub_loop_local_map->publish(local_map_cloud_msg);
                // 得到初始位姿
                Eigen::Affine3f pose_matrix = pcl::getTransformation(curr_infer_pose.x, curr_infer_pose.y, curr_infer_pose.z,
                                                                     curr_infer_pose.roll, curr_infer_pose.pitch, curr_infer_pose.yaw);

                PointCloud_XYZ::Ptr input_src_ds(new PointCloud_XYZ());
                pcl::VoxelGrid<Point_XYZ> downSamplePointCloudFilter;
                downSamplePointCloudFilter.setLeafSize(0.4, 0.4, 0.4);
                downSamplePointCloudFilter.setInputCloud(lidar_loop_buffer_copy.back());
                downSamplePointCloudFilter.filter(*input_src_ds);

                PointCloud_XYZ output_cloud;
                registration_ptr->clearTarget();
                registration_ptr->clearSource();
                registration_ptr->setInputTarget(local_map);
                registration_ptr->setInputSource(input_src_ds);
                registration_ptr->align(output_cloud, pose_matrix.matrix());
                if (registration_ptr->hasConverged())
                {
                    double x, y, z, roll, pitch, yaw;

                    Eigen::Matrix4d matrix_w_l = (registration_ptr->getFinalTransformation()).cast<double>(); // 激光雷达到世界坐标系的变换矩阵
                    /*******************************得到lidar在world系下的姿态************************************/
                    Eigen::Affine3d affine_w_l;
                    affine_w_l.matrix() = matrix_w_l;
                    pcl::getTranslationAndEulerAngles(affine_w_l, x, y, z, roll, pitch, yaw);
                    /*************************发布回环定位点云*************************/
                    Point_XYZRPY loop_pose;
                    loop_pose.x = x;
                    loop_pose.y = y;
                    loop_pose.z = z;
                    loop_pose.roll = roll;
                    loop_pose.pitch = pitch;
                    loop_pose.yaw = yaw;
                    PointCloud_XYZ loop_cloud = transformPointCloud(*(lidar_loop_buffer_copy.back()), loop_pose);
                    sensor_msgs::msg::PointCloud2 loop_cloud_msg;
                    pcl::toROSMsg(loop_cloud, loop_cloud_msg);
                    loop_cloud_msg.header.stamp = this->now();
                    loop_cloud_msg.header.frame_id = world_coor_sys;
                    pub_loop_cloud->publish(loop_cloud_msg);
                    /*********************更新eskf状态变量**************************/
                    if (pose_status != INITIALIZED)
                    {
                        pose_w_l_msg_with_stamp.pose.pose = tf2::toMsg(affine_w_l);
                        Eigen::Affine3d affine_i_l;
                        pcl::getTransformation(tf_i_l_x, tf_i_l_y, tf_i_l_z, tf_i_l_roll, tf_i_l_pitch, tf_i_l_yaw, affine_i_l);
                        Eigen::Affine3d affine_w_i = affine_w_l * affine_i_l.inverse();

                        pcl::getTranslationAndEulerAngles(affine_w_i, x, y, z, roll, pitch, yaw);

                        SO3 so3 = EulerToSO3(V3D(roll, pitch, yaw));
                        state_ikfom optimization_state_variable;

                        // optimization_state_variable.offset_T_L_I = Lidar_T_wrt_IMU;
                        // optimization_state_variable.offset_R_L_I = Lidar_R_wrt_IMU;

                        optimization_state_variable.rot = so3;

                        optimization_state_variable.pos(0) = x;
                        optimization_state_variable.pos(1) = y;
                        optimization_state_variable.pos(2) = z;
                        eskf.change_x(optimization_state_variable); // 更新kf的_x的状态

                        pose_status = INITIALIZED; // 定位初始化完成
                    }
                }
                else
                    RCLCPP_ERROR(this->get_logger(), "loop location fail.");
            }
        }
        loop_rate.sleep();
    }
}
// 构建局部增量地图
void lidar_localizer::build_local_incremental_map(geometry_msgs::msg::Pose &_pose)
{
    /******************************增量地图更新*******************************/
    // KD_TREE<Point_XYZRPYI>::PointVector search_result;
    std::vector<int> select_search_idx_set;
    std::vector<int> new_add_idx;
    // Point_XYZRPYI curr_pose;
    // curr_pose.x = _pose.position.x;
    // curr_pose.y = _pose.position.y;
    // curr_pose.z = _pose.position.z;

    Point_XYZ curr_position;
    curr_position.x = _pose.position.x;
    curr_position.y = _pose.position.y;
    curr_position.z = _pose.position.z;

    std::vector<float> search_dists;
    std::vector<int> search_idxes;

    // ikdtree_pose.Radius_Search(curr_pose, 3, search_result); // 在当前坐标下方圆15m搜素关键位姿
    // ikdtree_pose.Nearest_Search(curr_pose, NEAREST_NUM, search_result, pointSearchSqDis);
    kdtree_3dPose.nearestKSearch(curr_position, NEAREST_NUM, search_idxes, search_dists);
    for (size_t i = 0; i < search_idxes.size(); i++)
    {
        if (search_dists[i] > 10)
            continue;
        int search_key_idx = search_idxes[i];
        select_search_idx_set.push_back(search_key_idx);
        if (local_key_frames.count(search_key_idx) == 0)
        {
            PointCloud_XYZI cloud_xyzi;
            if (pcl::io::loadPCDFile<pcl::PointXYZI>(map_path + "/" + std::to_string(search_key_idx) + ".pcd", cloud_xyzi) == -1) // 加载地图库中关键帧点云
            {
                RCLCPP_WARN(this->get_logger(), (std::string("unable to open ") + std::to_string(search_key_idx) + ".pcd").c_str());
                continue;
            }
            Point_XYZRPY pose;
            pose.x = key_6dPoses.points[search_key_idx].x;
            pose.y = key_6dPoses.points[search_key_idx].y;
            pose.z = key_6dPoses.points[search_key_idx].z;
            pose.roll = key_6dPoses.points[search_key_idx].roll;
            pose.pitch = key_6dPoses.points[search_key_idx].pitch;
            pose.yaw = key_6dPoses.points[search_key_idx].yaw;
            PointCloud_XYZI tf_pcl = transformPointCloud(cloud_xyzi, pose);
            local_key_frames[search_key_idx] = tf_pcl;
#ifdef USE_IVOX
            // IVoxType::PointVector pts_added;
            // for (auto pt : tf_pcl.points)
            //     pts_added.push_back(pt);
            // p_ivox->AddPoints(pts_added);
            if (!FIRST_BUILD_INCREMENTAL_MAP)
                p_ivox->AddPoints(tf_pcl.points);
#endif
#ifdef USE_IKDTREE
            new_add_idx.push_back(search_key_idx);
#endif
        }
    }

    if (select_search_idx_set.empty())
        RCLCPP_WARN(this->get_logger(), "Unable to find keyframes within 10m range.Location may be lost.");

#ifdef USE_IVOX
    if (FIRST_BUILD_INCREMENTAL_MAP)
    {
        FIRST_BUILD_INCREMENTAL_MAP = false;
        PointCloud_XYZI::Ptr local_map(new PointCloud_XYZI());
        for (size_t i = 0; i < select_search_idx_set.size(); i++)
        {
            int search_key_idx = select_search_idx_set[i];
            *local_map += local_key_frames[search_key_idx];
        }
        p_ivox->AddPoints(local_map->points);
    }
#endif
#ifdef USE_IKDTREE
    if (ikdtree_local_map.Root_Node == nullptr)
    {
        /************************构建kd树*****************************/
        ikdtree_local_map.set_downsample_param(0.1); // 设置ikd-tree降采样参数
        PointCloud_XYZI::Ptr local_map(new PointCloud_XYZI());
        for (size_t i = 0; i < select_search_idx_set.size(); i++)
        {
            int search_key_idx = select_search_idx_set[i];
            *local_map += local_key_frames[search_key_idx];
        }
        ikdtree_local_map.Build(local_map->points); // 构建ikd-tree
    }
    else
    {
        /***************************更新增量地图******************************/
        KD_TREE<Point_XYZI>::PointVector PointToAdd;
        for (size_t i = 0; i < new_add_idx.size(); i++)
        {
            int search_key_idx = new_add_idx[i];
            PointCloud_XYZI pt_cloud_world = local_key_frames[search_key_idx];
            for (size_t i = 0; i < pt_cloud_world.points.size(); i++)
                PointToAdd.push_back(pt_cloud_world.points[i]);
            ikdtree_local_map.Add_Points(PointToAdd, true);
        }
    }
    /**************************动态删除不需要的点，加速kdtree搜索速度*****************************/
    KD_TREE<Point_XYZI>::PointVector need_delete_pts;
    for (auto element : local_key_frames)
    {
        bool b_find = false;
        for (size_t i = 0; i < select_search_idx_set.size(); i++)
        {
            if (element.first == select_search_idx_set[i])
            {
                b_find = true;
                break;
            }
        }
        if (!b_find)
        {
            for (int pt_idx = 0; pt_idx < element.second.points.size(); pt_idx++)
                need_delete_pts.push_back(element.second.points[pt_idx]);
        }
    }
    ikdtree_local_map.Delete_Points(need_delete_pts); // 删除ikd-tree中无用点
#endif
    // 删除在当前搜索结果中不存在的关键帧
    for (auto iter = local_key_frames.begin(); iter != local_key_frames.end();)
    {
        if (std::find(select_search_idx_set.begin(), select_search_idx_set.end(), iter->first) == select_search_idx_set.end())
            iter = local_key_frames.erase(iter);
        else
            iter++;
    }
}
// 计算残差信息
void lidar_localizer::h_share_model(state_ikfom &_state_variable, esekfom::dyn_share_datastruct<double> &ekfom_data)
{
    int pcl_size = undistort_pcl_ds->points.size();
    if (pcl_size == 0)
    {
        RCLCPP_ERROR(this->get_logger(), "lidar data is empty.");
        return;
    }
    std::vector<bool> pt_selected_flag(pcl_size, true);
    PointCloud_XYZI::Ptr pcl_selected(new PointCloud_XYZI(pcl_size, 1));
    PointCloud_XYZI::Ptr normvec(new PointCloud_XYZI(pcl_size, 1));
    PointCloud_XYZI::Ptr normvec_selected(new PointCloud_XYZI(pcl_size, 1));
    // pcl_selected.reset(new PointCloud_XYZI(pcl_size, 1));
    // normvec.reset(new PointCloud_XYZI(pcl_size, 1));
    // normvec_selected.reset(new PointCloud_XYZI(pcl_size, 1));

    // 对每个特征点进行残差计算
#pragma omp parallel for num_threads(8)
    for (int i = 0; i < pcl_size; i++)
    {
        Point_XYZI pt_world;
        Point_XYZI pt_lidar = undistort_pcl_ds->points[i];
        // 将点转换到世界坐标系下
        V3D v3d_lidar(pt_lidar.x, pt_lidar.y, pt_lidar.z);
        V3D v3d_world(_state_variable.rot * (_state_variable.offset_R_L_I * v3d_lidar + _state_variable.offset_T_L_I) + _state_variable.pos); // 将点转换到世界坐标系下，从而计算残差

        pt_world.x = v3d_world(0);
        pt_world.y = v3d_world(1);
        pt_world.z = v3d_world(2);
        pt_world.intensity = pt_lidar.intensity;

        auto &nearest_points = nearest_point_set[i];

        if (ekfom_data.converge) // 如果收敛了
        {
            // 在已构造的地图上查找特征点的最近邻
#ifdef USE_IKDTREE
            std::vector<float> pointSearchSqDis(NUM_MATCH_POINTS);

            ikdtree_local_map.Nearest_Search(pt_world, NUM_MATCH_POINTS, nearest_points, pointSearchSqDis);
            // 如果最近邻的点数小于NUM_MATCH_POINTS或者最近邻的点到特征点的距离大于5m，则认为该点不是有效点
            pt_selected_flag[i] = nearest_points.size() < NUM_MATCH_POINTS ? false : pointSearchSqDis[NUM_MATCH_POINTS - 1] > 5 ? false
                                                                                                                                : true;
#endif
#ifdef USE_IVOX
            p_ivox->GetClosestPoint(pt_world, nearest_points, NUM_MATCH_POINTS, 5.0);
            pt_selected_flag[i] = nearest_points.size() < NUM_MATCH_POINTS ? false : true;
#endif
        }
        // 如果该点不是有效点
        if (!pt_selected_flag[i])
            continue;
        VF(4)
        pabcd;                       // 平面点信息
        pt_selected_flag[i] = false; // 将该点设置为无效点，用来计算是否为平面点
        // 拟合平面方程ax+by+cz+d=0并求解点到平面距离
        if (esti_plane(pabcd, nearest_points, 0.1f))
        {
            float pd2 = pabcd(0) * pt_world.x + pabcd(1) * pt_world.y + pabcd(2) * pt_world.z + pabcd(3); // 计算点到平面的距离
            float threshold = 1 - 0.9 * fabs(pd2) / sqrt(v3d_lidar.norm());
            if (threshold > 0.9) // 大于阈值
            {
                pt_selected_flag[i] = true;      // 再次恢复为有效点
                normvec->points[i].x = pabcd(0); // 将法向量存储至normvec
                normvec->points[i].y = pabcd(1);
                normvec->points[i].z = pabcd(2);
                normvec->points[i].intensity = pd2; // 将点到平面的距离存储至normvec的intensity中
            }
        }
    }
    int effct_pt_num = 0; // 有效的特征点数

    for (int i = 0; i < pcl_size; i++)
    {
        // 根据point_selected_surf状态判断哪些点是可用的
        if (pt_selected_flag[i])
        {

            // body点存到lidarCloudOri中
            pcl_selected->points[effct_pt_num] = undistort_pcl_ds->points[i]; // 将降采样后的每个特征点存储至lidarCloudOri
            normvec_selected->points[effct_pt_num] = normvec->points[i];      // 拟合平面点存到corr_normvect中
            effct_pt_num++;                                                   // 有效特征点数加1
        }
    }
    if (effct_pt_num < 1) // 如果effct_feat_num小于1，则返回
    {
        ekfom_data.valid = false;
        RCLCPP_WARN(this->get_logger(), "No Effective Points! \n");
        return;
    }
    // 测量雅可比矩阵H和测量向量的计算H=J*P*J’
    ekfom_data.h_x = Eigen::MatrixXd::Zero(effct_pt_num, 12); // 测量雅可比矩阵H，论文中的23
    ekfom_data.h.resize(effct_pt_num);                        // 测量向量h

    // 求观测值与误差的雅克比矩阵，如论文式14以及式12、13
    for (int i = 0; i < effct_pt_num; i++)
    {
        // 拿到的有效点的坐标
        const pcl::PointXYZI &lidar_p = pcl_selected->points[i];
        V3D point_this_be(lidar_p.x, lidar_p.y, lidar_p.z);
        M3D point_be_crossmat;                                                                        // 计算点的叉矩阵（向量的反对称矩阵）
        point_be_crossmat << SKEW_SYM_MATRX(point_this_be);                                           // 从向量点值转化到反对称矩阵
        V3D point_this = _state_variable.offset_R_L_I * point_this_be + _state_variable.offset_T_L_I; // 转换到IMU坐标系下
        M3D point_crossmat;
        point_crossmat << SKEW_SYM_MATRX(point_this); // 计算IMU中的点的叉矩阵

        /*** get the normal vector of closest surface/corner ***/
        // 得到对应的曲面/角的法向量
        const pcl::PointXYZI &norm_p = normvec_selected->points[i];
        V3D norm_vec(norm_p.x, norm_p.y, norm_p.z);

        /*** calculate the Measuremnt Jacobian matrix H ***/
        V3D C(_state_variable.rot.conjugate() * norm_vec);
        V3D A(point_crossmat * C);
        if (1)
        {
            V3D B(point_be_crossmat * _state_variable.offset_R_L_I.conjugate() * C); // _state_variable.rot.conjugate()*norm_vec);
            ekfom_data.h_x.block<1, 12>(i, 0) << norm_p.x, norm_p.y, norm_p.z, VEC_FROM_ARRAY(A), VEC_FROM_ARRAY(B), VEC_FROM_ARRAY(C);
        }
        else
        {
            ekfom_data.h_x.block<1, 12>(i, 0) << norm_p.x, norm_p.y, norm_p.z, VEC_FROM_ARRAY(A), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0;
        }

        /*** Measuremnt: distance to the closest surface/corner ***/
        ekfom_data.h(i) = -norm_p.intensity; // 点到面的距离
    }
}
// 字符分割
static std::vector<std::string> splitString(const std::string &str, char delimiter)
{
    std::vector<std::string> result;
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != std::string::npos)
    {
        result.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    result.push_back(str.substr(start));
    return result;
}
// 加载关键帧位姿文件
void lidar_localizer::load_key_pose_file()
{
    std::string strLine;
    std::ifstream pose_file(map_path + "/posture.txt", std::ios::in);
    if (!pose_file.is_open())
        RCLCPP_ERROR(this->get_logger(), "can not open posture file.");

    while (getline(pose_file, strLine))
    {
        if (strLine.empty())
            continue;
        std::vector<std::string> str_splits = splitString(strLine, ',');
        if (str_splits.size() != 7)
            RCLCPP_ERROR(this->get_logger(), "posture size should be seven.");
        Point_XYZRPYI pose_6d;
        pose_6d.x = std::stof(str_splits[0]);
        pose_6d.y = std::stof(str_splits[1]);
        pose_6d.z = std::stof(str_splits[2]);
        pose_6d.roll = std::stof(str_splits[3]);
        pose_6d.pitch = std::stof(str_splits[4]);
        pose_6d.yaw = std::stof(str_splits[5]);
        pose_6d.idx = std::stoi(str_splits[6]);
        key_6dPoses.points.push_back(pose_6d);

        Point_XYZ pose_3d;
        pose_3d.x = pose_6d.x;
        pose_3d.y = pose_6d.y;
        pose_3d.z = pose_6d.z;
        key_3dPoses->points.push_back(pose_3d);
    }
    // ikdtree_pose.Build(key_6dPoses.points);
    kdtree_3dPose.setInputCloud(key_3dPoses);
}
// 定位
void lidar_localizer::location()
{
    rclcpp::WallRate loop_rate(100.0); // 100hz
    unsigned int cnt = 0;
    while (rclcpp::ok())
    {
        loop_rate.sleep();

        PointCloud_XYZI::Ptr undistort_pcl(new PointCloud_XYZI()); // 单帧点云去畸变的特征点
        // undistort_pcl.reset(new PointCloud_XYZI());

        // 是否初始化
        if (pose_status < INITIALIZED)
            continue;

        if (!data_synchronization(measure_group))
            continue;

        p_imu->Process(measure_group, eskf, undistort_pcl);

        state_variable = eskf.get_x();

        if (undistort_pcl->empty() || (undistort_pcl == NULL))
        {
            // RCLCPP_WARN(this->get_logger(), "No point, skip this scan!\n");
            continue;
        }
        // std::cout << "<<<<<<<<<<<<<<<<<<<<<<<<<location>>>>>>>>>>>>>>>>>>>>>>" << std::endl;
        PointCloud_XYZI::Ptr thisLidarFrame(new PointCloud_XYZI());
        pcl::copyPointCloud(*undistort_pcl, *thisLidarFrame);

        pcl::VoxelGrid<pcl::PointXYZI> downSizeFilterCloud;
        downSizeFilterCloud.setLeafSize(0.5, 0.5, 0.5);
        downSizeFilterCloud.setInputCloud(thisLidarFrame);
        downSizeFilterCloud.filter(*undistort_pcl_ds);

        build_local_incremental_map(pose_w_l_msg_with_stamp.pose.pose); // 构建局部增量地图
        /********************发布局部地图*************************/
        // PointVector().swap(ikdtree_local_map.PCL_Storage);                                                 // 清空
        // ikdtree_local_map.flatten(ikdtree_local_map.Root_Node, ikdtree_local_map.PCL_Storage, NOT_RECORD); // 展平ikdtree
        // PointCloud_XYZI::Ptr local_map(new PointCloud_XYZI());
        // local_map.reset(new PointCloud_XYZI());
        // local_map->points = ikdtree_local_map.PCL_Storage; // ikd-tree赋给局部地图
        // sensor_msgs::msg::PointCloud2 local_map_cloud_msg;
        // pcl::toROSMsg(*local_map, local_map_cloud_msg);
        // local_map_cloud_msg.header.stamp = this->now();
        // local_map_cloud_msg.header.frame_id = world_coor_sys;
        // pub_local_map->publish(local_map_cloud_msg);
        // 迭代卡尔曼滤波器更新，更新地图信息
        nearest_point_set.resize(undistort_pcl_ds->points.size());
        double solve_H_time = 0;
        eskf.update_iterated_dyn_share_modified(0.001, solve_H_time);

        state_variable = eskf.get_x();

        V3D euler_i_l = SO3ToEuler(state_variable.offset_R_L_I); // lidar到imu的旋转变换

        V3D euler_w_i = SO3ToEuler(state_variable.rot); // imu到word的旋转变换

        Eigen::Affine3f affine_w_i = pcl::getTransformation(state_variable.pos(0), state_variable.pos(1), state_variable.pos(2), euler_w_i[0], euler_w_i[1], euler_w_i[2]);
        Eigen::Affine3f affine_i_l = pcl::getTransformation(state_variable.offset_T_L_I(0), state_variable.offset_T_L_I(1), state_variable.offset_T_L_I(2),
                                                            euler_i_l[0], euler_i_l[1], euler_i_l[2]);
        Eigen::Affine3d affine_w_l = (affine_w_i * affine_i_l).cast<double>();

        // 得到lidar在world系下的位姿
        pose_w_l_msg_with_stamp.pose.pose = tf2::toMsg(affine_w_l);
        /**************************************发布lidar在world系下的位姿**************************************/
        // geometry_msgs::msg::PoseWithCovarianceStamped pose_w_l_msg_with_stamp;
        pose_w_l_msg_with_stamp.header.stamp = curr_lidar_timestamp;
        pose_w_l_msg_with_stamp.header.frame_id = world_coor_sys;
        pose_w_l_msg_with_stamp.pose.covariance = pose_covariance;
        pub_lidar_pose->publish(pose_w_l_msg_with_stamp);
        /**********************************发布world系下lidar点云***************************************/
        double x, y, z, roll, pitch, yaw;
        pcl::getTranslationAndEulerAngles(affine_w_l, x, y, z, roll, pitch, yaw);
        Point_XYZRPY _pose;
        _pose.x = x;
        _pose.y = y;
        _pose.z = z;
        _pose.roll = roll;
        _pose.pitch = pitch;
        _pose.yaw = yaw;
        PointCloud_XYZI cloud = transformPointCloud(*(undistort_pcl_ds), _pose);
        sensor_msgs::msg::PointCloud2 cloud_msg;
        pcl::toROSMsg(cloud, cloud_msg);
        cloud_msg.header.stamp = this->now();
        cloud_msg.header.frame_id = world_coor_sys;
        pub_cloud->publish(cloud_msg);

        /******************************************广播坐标系*********************************************/
        geometry_msgs::msg::TransformStamped transform_stamped;
        transform_stamped.header.frame_id = world_coor_sys;
        transform_stamped.child_frame_id = "lidar_link";
        transform_stamped.header.stamp = curr_lidar_timestamp;

        transform_stamped.transform.translation.x = pose_w_l_msg_with_stamp.pose.pose.position.x;
        transform_stamped.transform.translation.y = pose_w_l_msg_with_stamp.pose.pose.position.y;
        transform_stamped.transform.translation.z = pose_w_l_msg_with_stamp.pose.pose.position.z;

        tf2::Quaternion tf_quaternion;
        tf2::fromMsg(pose_w_l_msg_with_stamp.pose.pose.orientation, tf_quaternion);
        transform_stamped.transform.rotation.x = tf_quaternion.x();
        transform_stamped.transform.rotation.y = tf_quaternion.y();
        transform_stamped.transform.rotation.z = tf_quaternion.z();
        transform_stamped.transform.rotation.w = tf_quaternion.w();
        tf_broadcaster.sendTransform(transform_stamped);

        pose_status = NORMAL;
    }
}
// 得到坐标系变换
bool lidar_localizer::get_tf(std::string target_frame, std::string source_frame, geometry_msgs::msg::TransformStamped &transform_stamped)
{
    if (target_frame == source_frame)
    {
        transform_stamped.header.stamp = this->now();
        transform_stamped.header.frame_id = target_frame;
        transform_stamped.child_frame_id = source_frame;
        transform_stamped.transform.translation.x = 0.0;
        transform_stamped.transform.translation.y = 0.0;
        transform_stamped.transform.translation.z = 0.0;
        transform_stamped.transform.rotation.x = 0.0;
        transform_stamped.transform.rotation.y = 0.0;
        transform_stamped.transform.rotation.z = 0.0;
        transform_stamped.transform.rotation.w = 1.0;
        return true;
    }
    try
    {
        transform_stamped = tf_buffer.lookupTransform(target_frame, source_frame, tf2::TimePointZero, tf2::Duration(1000000000));
        return true;
    }
    catch (tf2::TransformException &ex)
    {
        RCLCPP_ERROR(this->get_logger(), "Could not transform %s to %s: %s", source_frame.c_str(), target_frame.c_str(), ex.what());
        return false;
    }
}
// 从gnss得到lidar在world系下的姿态
geometry_msgs::msg::Pose lidar_localizer::get_infer_position(geometry_msgs::msg::TransformStamped &_tf_g_l,
                                                             geometry_msgs::msg::PoseWithCovarianceStamped &gnss_pose_with_stamp)
{
    geometry_msgs::msg::Pose pose_msg;
    // gnss坐标系到map坐标系的变换
    tf2::Transform tf_map2gnss;
    tf2::Transform tf_gnss2lidar;
    tf2::fromMsg(gnss_pose_with_stamp.pose.pose, tf_map2gnss);

    tf2::fromMsg(_tf_g_l.transform, tf_gnss2lidar);
    tf2::Transform tf_map2lidar = tf_map2gnss * tf_gnss2lidar;

    tf2::toMsg(tf_map2lidar, pose_msg);

    return pose_msg;
}

int main(int argc, char **argv)
{
    rclcpp::init(argc, argv);

    rclcpp::NodeOptions options;
    options.use_intra_process_comms(true);
    rclcpp::executors::MultiThreadedExecutor lidar_localizer_exe;
    auto lidar_localizer_node = std::make_shared<lidar_localizer>("lidar_localizer", options);
    lidar_localizer_exe.add_node(lidar_localizer_node);

    std::thread loop_detection_thread(&lidar_localizer::loop_detection, lidar_localizer_node);
    std::thread location_thread(&lidar_localizer::location, lidar_localizer_node);

    lidar_localizer_exe.spin();
    rclcpp::shutdown();

    loop_detection_thread.join();
    location_thread.join();

    return 0;
}
