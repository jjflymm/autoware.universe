#include "lidar_localizer/imu_processing.hpp"

static const bool time_list(Point_XYZIT &x, Point_XYZIT &y)
{
    return (x.time < y.time);
};

ImuProcess::ImuProcess()
    : b_first_frame_(true), imu_need_init_(true), start_timestamp_(-1) // imu构造函数
{
    init_iter_num = 1;       // 初始化迭代次数
    Q = process_noise_cov(); // 噪声协方差初始化
    cov_acc = V3D(0.1, 0.1, 0.1);
    cov_gyr = V3D(0.1, 0.1, 0.1);
    cov_bias_gyr = V3D(0.0001, 0.0001, 0.0001);
    cov_bias_acc = V3D(0.0001, 0.0001, 0.0001);
    mean_acc = V3D(0, 0, -1.0);
    mean_gyr = V3D(0, 0, 0);
    angvel_last = V3D(0, 0, 0);        // 3*1上一帧角速度初始化
    Lidar_T_wrt_IMU = V3D(0, 0, 0);    // 3*1激光雷达到imu的平移
    Lidar_R_wrt_IMU = M3D::Identity(); // 3*3激光雷达到imu旋转矩阵
                                       // last_imu_.reset(new sensor_msgs::Imu());//上一帧imu初始化
}

ImuProcess::~ImuProcess() {}

void ImuProcess::Reset() // 重置参数
{
    // ROS_WARN("Reset ImuProcess");
    mean_acc = V3D(0, 0, -1.0);
    mean_gyr = V3D(0, 0, 0);
    angvel_last = V3D(0, 0, 0);
    imu_need_init_ = true;
    start_timestamp_ = -1;
    init_iter_num = 1;
    v_imu_.clear();  // imu队列清空
    IMUpose.clear(); // imu位姿清空
    // last_imu_.reset(new sensor_msgs::Imu());//上一帧imu初始化
    cur_pcl_un_.reset(new PointCloud_XYZIT()); // 当前未去畸变的点云初始化
}

void ImuProcess::set_extrinsic(const MD(4, 4) & T) // 设置4*4变换矩阵T，传入外参r,t
{
    // block解析P.block<rows, cols>(i, j)  P(i+1 : i+rows, j+1 : j+cols) i,j开始，rows行cols列
    Lidar_T_wrt_IMU = T.block<3, 1>(0, 3);
    Lidar_R_wrt_IMU = T.block<3, 3>(0, 0);
}

void ImuProcess::set_extrinsic(const V3D &transl)
{
    Lidar_T_wrt_IMU = transl;      // 设置3*1平移矩阵
    Lidar_R_wrt_IMU.setIdentity(); // 设置旋转矩阵为单位矩阵
}

void ImuProcess::set_extrinsic(const V3D &transl, const M3D &rot)
{
    Lidar_T_wrt_IMU = transl;
    Lidar_R_wrt_IMU = rot;
}

void ImuProcess::set_gyr_cov(const V3D &scaler)
{
    cov_gyr_scale = scaler;
}

void ImuProcess::set_acc_cov(const V3D &scaler)
{
    cov_acc_scale = scaler;
}

void ImuProcess::set_gyr_bias_cov(const V3D &b_g)
{
    cov_bias_gyr = b_g;
}

void ImuProcess::set_acc_bias_cov(const V3D &b_a)
{
    cov_bias_acc = b_a;
}

void ImuProcess::IMU_init(const MeasureGroup &meas, esekfom::esekf<state_ikfom, 12, input_ikfom> &kf_state, int &N)
{
    /** 1. initializing the gravity, gyro bias, acc and gyro covariance
     ** 2. normalize the acceleration measurenments to unit gravity **/

    V3D cur_acc, cur_gyr; // 当前加速度、当前角速度

    if (b_first_frame_) // 是否是第一帧
    {
        Reset(); // 重置参数
        N = 1;
        b_first_frame_ = false;
        const auto &imu_acc = meas.imu.front().linear_acceleration;
        const auto &gyr_acc = meas.imu.front().angular_velocity;
        mean_acc << imu_acc.x, imu_acc.y, imu_acc.z;
        mean_gyr << gyr_acc.x, gyr_acc.y, gyr_acc.z;
        first_lidar_time = meas.lidar_beg_time;
    }

    for (const auto &imu : meas.imu)
    {
        const auto &imu_acc = imu.linear_acceleration;
        const auto &gyr_acc = imu.angular_velocity;
        cur_acc << imu_acc.x, imu_acc.y, imu_acc.z;
        cur_gyr << gyr_acc.x, gyr_acc.y, gyr_acc.z;

        mean_acc += (cur_acc - mean_acc) / N;
        mean_gyr += (cur_gyr - mean_gyr) / N;
        // 方差递推公式见：https://blog.csdn.net/wuqinlong/article/details/78432574
        cov_acc = cov_acc * (N - 1.0) / N + (cur_acc - mean_acc).cwiseProduct(cur_acc - mean_acc) * (N - 1.0) / (N * N);
        cov_gyr = cov_gyr * (N - 1.0) / N + (cur_gyr - mean_gyr).cwiseProduct(cur_gyr - mean_gyr) * (N - 1.0) / (N * N);

        // cout<<"acc norm: "<<cur_acc.norm()<<" "<<mean_acc.norm()<<endl;

        N++;
    }
    state_ikfom init_state = kf_state.get_x();
    init_state.grav = S2(-mean_acc / mean_acc.norm() * G_m_s2);

    // state_inout.rot = Eye3d; // Exp(mean_acc.cross(V3D(0, 0, -1 / scale_gravity)));
    init_state.bg = mean_gyr;                  // 用陀螺仪的平均值作为陀螺仪的零偏
    init_state.offset_T_L_I = Lidar_T_wrt_IMU; // Lidar到IMU的平移
    init_state.offset_R_L_I = Lidar_R_wrt_IMU; // Lidar到IMU的旋转
    kf_state.change_x(init_state);

    esekfom::esekf<state_ikfom, 12, input_ikfom>::cov init_P = kf_state.get_P();
    init_P.setIdentity();
    init_P(6, 6) = init_P(7, 7) = init_P(8, 8) = 0.00001;
    init_P(9, 9) = init_P(10, 10) = init_P(11, 11) = 0.00001;
    init_P(15, 15) = init_P(16, 16) = init_P(17, 17) = 0.0001;
    init_P(18, 18) = init_P(19, 19) = init_P(20, 20) = 0.001;
    init_P(21, 21) = init_P(22, 22) = 0.00001;
    kf_state.change_P(init_P);
    last_imu_ = meas.imu.back();
    last_lidar_end_time_=meas.lidar_end_time; 
}

void ImuProcess::UndistortPcl(const MeasureGroup &meas, esekfom::esekf<state_ikfom, 12, input_ikfom> &kf_state, PointCloud_XYZI &undistort_pcl)
{
    /*** add the imu of the last frame-tail to the of current frame-head ***/
    std::vector<pcl::PointXYZI, Eigen::aligned_allocator<pcl::PointXYZI>>().swap(undistort_pcl.points); // 释放内存
    auto v_imu = meas.imu;
    v_imu.push_front(last_imu_);
    const double &imu_beg_time = v_imu.front().header.stamp.sec + v_imu.front().header.stamp.nanosec * 1e-9; // 当前帧头部的IMU时间戳
    const double &imu_end_time = v_imu.back().header.stamp.sec + v_imu.back().header.stamp.nanosec * 1e-9;   // 当前帧尾部的IMU时间戳
    const double &pcl_beg_time = meas.lidar_beg_time;                                                        // 当前帧点云起始时间
    const double &pcl_end_time = meas.lidar_end_time;                                                        // 当前帧点云结束时间
    /*** sort point clouds by offset time ***/
    PointCloud_XYZIT distort_pcl = *(meas.lidar); // 点云数据
    undistort_pcl.header.stamp = distort_pcl.header.stamp;
    sort(distort_pcl.points.begin(), distort_pcl.points.end(), time_list); // 点云中的点的时间戳排序，从小到大

    /*** Initialize IMU pose ***/
    state_ikfom imu_state = kf_state.get_x(); // 获取上次KF估计的后验状态作为本次IMU预测的初始状态
    IMUpose.clear();                          // 清空IMUpose
    // 将初始状态加入IMUpose中，包含有时间间隔，上一帧加速度，上一帧角速度，上一帧速度，上一帧位置，上一帧旋转矩阵
    IMUpose.push_back(set_pose6d(imu_beg_time, acc_s_last, angvel_last, imu_state.vel, imu_state.pos, imu_state.rot.toRotationMatrix()));

    /*** forward propagation at each imu point ***/
    V3D angvel_avr, acc_avr, acc_imu, vel_imu, pos_imu; // 平均角速度、平均加速度、imu加速度、imu速度、imu位置
    M3D R_imu;                                          // imu旋转矩阵
    double dt = 0;                                      // 时间间隔

    input_ikfom in; // eskf传入参数
    for (auto it_imu = v_imu.begin(); it_imu < (v_imu.end() - 1); it_imu++)
    {
        auto head = *(it_imu);     // 当前帧imu数据
        auto tail = *(it_imu + 1); // 下一帧imu数据
        // 判断IMU时间戳是否大于上一帧激光雷达结束时间戳
        // if ((tail.header.stamp.sec + tail.header.stamp.nanosec * 1e-9) < last_lidar_end_time_)
        //     continue;

        // IMU中值积分
        angvel_avr << 0.5 * (head.angular_velocity.x + tail.angular_velocity.x),
            0.5 * (head.angular_velocity.y + tail.angular_velocity.y),
            0.5 * (head.angular_velocity.z + tail.angular_velocity.z);
        acc_avr << 0.5 * (head.linear_acceleration.x + tail.linear_acceleration.x),
            0.5 * (head.linear_acceleration.y + tail.linear_acceleration.y),
            0.5 * (head.linear_acceleration.z + tail.linear_acceleration.z);

        // fout_imu << setw(10) << head->header.stamp.toSec() - first_lidar_time << " " << angvel_avr.transpose() << " " << acc_avr.transpose() << endl;

        acc_avr = acc_avr * G_m_s2 / mean_acc.norm(); // - state_inout.ba;

        // 雷达第一个点的时间戳在head和tail中间
        // if ((head.header.stamp.sec + head.header.stamp.nanosec * 1e-9) < last_lidar_end_time_)
        //     dt = (tail.header.stamp.sec + tail.header.stamp.nanosec * 1e-9) - last_lidar_end_time_;
        // else
        // IMU时间间隔
        dt = (tail.header.stamp.sec + tail.header.stamp.nanosec * 1e-9) - (head.header.stamp.sec + head.header.stamp.nanosec * 1e-9);

        in.acc = acc_avr;
        in.gyro = angvel_avr;
        Q.block<3, 3>(0, 0).diagonal() = cov_gyr;
        Q.block<3, 3>(3, 3).diagonal() = cov_acc;
        Q.block<3, 3>(6, 6).diagonal() = cov_bias_gyr;
        Q.block<3, 3>(9, 9).diagonal() = cov_bias_acc;
        kf_state.predict(dt, Q, in);
        /* save the poses at each IMU measurements */
        imu_state = kf_state.get_x();                          // 获得预测的状态
        angvel_last = angvel_avr - imu_state.bg;               // 测量角速度减去角速度零偏
        acc_s_last = imu_state.rot * (acc_avr - imu_state.ba); // 测量加速度减去加速度零偏

        for (int i = 0; i < 3; i++)
        {
            acc_s_last[i] += imu_state.grav[i]; // 加上重力加速度
        }
        double &&tail_time = tail.header.stamp.sec + tail.header.stamp.nanosec * 1e-9;

        IMUpose.push_back(set_pose6d(tail_time, acc_s_last, angvel_last, imu_state.vel, imu_state.pos, imu_state.rot.toRotationMatrix()));
    }
    /*** calculated the pos and attitude prediction at the frame-end ***/
    // 预测最后一个激光雷达点在IMU坐标系中的状态
    double note = pcl_end_time > imu_end_time ? 1.0 : -1.0;
    dt = note * (pcl_end_time - imu_end_time);
    kf_state.predict(dt, Q, in);
    imu_state = kf_state.get_x();
    last_imu_ = meas.imu.back();
    last_lidar_end_time_ = pcl_end_time;

    /*** undistort each lidar point (backward propagation) ***/
    if (distort_pcl.points.begin() == distort_pcl.points.end())
        return;
        
    auto it_pcl = distort_pcl.points.end() - 1;
    for (auto it_kp = IMUpose.end(); it_kp != IMUpose.begin(); it_kp--)
    {
        auto head = it_kp - 1;
        auto tail = it_kp;
        R_imu << MAT_FROM_ARRAY(head->rot); // 3*3旋转矩阵
        // cout<<"head imu acc: "<<acc_imu.transpose()<<endl;
        vel_imu << VEC_FROM_ARRAY(head->vel);    // 3*1速度
        pos_imu << VEC_FROM_ARRAY(head->pos);    // 3*1位置
        acc_imu << VEC_FROM_ARRAY(tail->acc);    // 3*1加速度
        angvel_avr << VEC_FROM_ARRAY(tail->gyr); // 3*1角速度
        // 不断的循环遍历点云
        for (; it_pcl->time > head->time; it_pcl--)
        {
            dt = it_pcl->time - head->time;
            /* Transform to the 'end' frame, using only the rotation
             * Note: Compensation direction is INVERSE of Frame's moving direction
             * So if we want to compensate a point at timestamp-i to the frame-e
             * P_compensate = R_imu_e ^ T * (R_i * P_i + T_ei) where T_ei is represented in global frame */
            M3D R_i(R_imu * Exp(angvel_avr, dt));

            V3D P_i(it_pcl->x, it_pcl->y, it_pcl->z);
            V3D T_ei(pos_imu + vel_imu * dt + 0.5 * acc_imu * dt * dt - imu_state.pos);
            // 见formula.png公式推导
            V3D P_compensate = imu_state.offset_R_L_I.conjugate() *
                               (imu_state.rot.conjugate() * (R_i * (imu_state.offset_R_L_I * P_i + imu_state.offset_T_L_I) + T_ei) - imu_state.offset_T_L_I); // not accurate!

            // save Undistorted points and their rotation
            it_pcl->x = P_compensate(0);
            it_pcl->y = P_compensate(1);
            it_pcl->z = P_compensate(2);

            if (fabs(it_pcl->x) > 1e9 || fabs(it_pcl->y) > 1e9 || fabs(it_pcl->z) > 1e9)
                continue;
            
            if(isnan(it_pcl->x) || isnan(it_pcl->y) && isnan(it_pcl->z) || isnan(it_pcl->intensity))
				continue;

            undistort_pcl.points.push_back(pcl::PointXYZI(it_pcl->x, it_pcl->y, it_pcl->z, it_pcl->intensity));

            if (it_pcl == distort_pcl.points.begin())
                break;
        }
    }
}

void ImuProcess::Process(const MeasureGroup &meas, esekfom::esekf<state_ikfom, 12, input_ikfom> &kf_state, PointCloud_XYZI::Ptr cur_pcl_un_)
{
    if (meas.imu.empty())
        return;
    assert(meas.lidar != nullptr);
    if (imu_need_init_)
    {
        /// The very first lidar frame
        IMU_init(meas, kf_state, init_iter_num);

        imu_need_init_ = true;

        last_imu_ = meas.imu.back();

        state_ikfom imu_state = kf_state.get_x();
        if (init_iter_num > MAX_INI_COUNT)
        {
            cov_acc *= pow(G_m_s2 / mean_acc.norm(), 2);
            imu_need_init_ = false;

            cov_acc = cov_acc_scale;
            cov_gyr = cov_gyr_scale;
            RCLCPP_INFO(rclcpp::get_logger("imu"), "IMU Initial Done");
        }

        return;
    }

    UndistortPcl(meas, kf_state, *cur_pcl_un_);
}
