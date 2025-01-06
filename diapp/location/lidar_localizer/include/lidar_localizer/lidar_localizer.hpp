#ifndef LOCATION_LIDAR_LOCALIZER
#define LOCATION_LIDAR_LOCALIZER

#include <rclcpp/rclcpp.hpp>
#include <tf2/transform_datatypes.h>
#include <tf2/LinearMath/Quaternion.h>
#include <tf2/LinearMath/Transform.h>
#include <tf2_ros/transform_listener.h>
#include <tf2_ros/transform_broadcaster.h>
#include <tf2_ros/buffer.h>
#include <geometry_msgs/msg/transform_stamped.hpp>
#include <sensor_msgs/msg/nav_sat_fix.hpp>
#include <geometry_msgs/msg/quaternion_stamped.hpp>
#include <geometry_msgs/msg/pose_with_covariance_stamped.hpp>
#include <tf2_geometry_msgs/tf2_geometry_msgs.hpp>
#include <sensor_msgs/msg/point_cloud2.hpp>
#include <sensor_msgs/msg/imu.hpp>
#include <tf2_eigen/tf2_eigen.h>
#include <std_msgs/msg/header.h>
#include <Eigen/Core>

// c++
#include <cmath>
#include <mutex>
#include <thread>
#include <boost/circular_buffer.hpp>

#include <omp.h>
// using pcl
#include <pcl/kdtree/kdtree_flann.h>
#define PCL_NO_PRECOMPILE
#include <pcl/point_cloud.h>
#include <pcl/point_types.h>
#include <pcl/search/impl/search.hpp>
#include <pcl/range_image/range_image.h>
#include <pcl/common/common.h>
#include <pcl/common/transforms.h>
#include <pcl/io/pcd_io.h>
#include <pcl/filters/voxel_grid.h>
#include <pcl/filters/crop_box.h>
#include <pcl_conversions/pcl_conversions.h>

#include "lidar_localizer/point_type.hpp"

#ifdef USE_VGICP_CUDA
#include "fast_gicp/ndt/ndt_cuda.hpp"
#include "fast_gicp/gicp/fast_vgicp_cuda.hpp"
#else
#include "fast_gicp/gicp/fast_gicp.hpp"
#include "fast_gicp/gicp/fast_gicp_st.hpp"
#include "fast_gicp/gicp/fast_vgicp.hpp"
#endif

#ifdef USE_IVOX
#include "ivox3d/ivox3d.h"
using namespace faster_lio;
#endif
#ifdef USE_IKDTREE
// using ikdtree
#include "ikd_tree/ikd_Tree.hpp"
#endif

#include "LidarIris/LidarIris.h"

#include "lidar_localizer/imu_processing.hpp"

#include "lidar_localizer/utility.hpp"

static const int NEAREST_NUM = 6;

// 定位状态
enum POSE_STATUS
{
    UNKONWN,
    ERROR,
    UNINITIALIZE,
    INITIALIZING,
    INITIALIZED,
    NORMAL
};

class lidar_localizer : public rclcpp::Node
{
public:
    lidar_localizer(std::string node_name, const rclcpp::NodeOptions &options);
    void loop_detection();
    void location();

private:
    /**************************变量****************************/
    double lidar_compensation_time;
    double imu_compensation_time;
    
    double lidar_min_depth_range, lidar_max_depth_range;
    std::mutex mtx_buffer;
    std::condition_variable sig_buffer;
    std::string map_path;   // 地图文件路劲
    int NUM_MAX_ITERATIONS; // 最大迭代次数
    POSE_STATUS pose_status;

    geometry_msgs::msg::PoseWithCovarianceStamped loop_pose;                    // 回环位姿
    geometry_msgs::msg::PoseWithCovarianceStamped lidar_pose;                   // 激光雷达位姿
    std::deque<geometry_msgs::msg::PoseWithCovarianceStamped> gnss_pose_buffer; // gnss在world系下的位姿队列
    std::deque<PointCloud_XYZ::Ptr> lidar_loop_buffer;                          // 用于回环检测的激光雷达缓存队列
    std::deque<sensor_msgs::msg::Imu> imu_buffer;                               // imu数据缓存队列
    std::deque<PointCloud_XYZIT::Ptr> lidar_buffer;                             // 激光雷达数据缓存队列

    PointCloud_XYZI::Ptr undistort_pcl_ds; // 下采样的去畸变激光雷达点云
    MeasureGroup measure_group;            // 测量组，包括lidar、imu数据

    // 坐标系监听
    tf2_ros::Buffer tf_buffer;
    tf2_ros::TransformListener tf_listener;

    tf2_ros::TransformBroadcaster tf_broadcaster; // 坐标系广播器
    // 当前激光雷达时间戳
    rclcpp::Time curr_lidar_timestamp;

    // 位姿协方差
    std::array<double, 36> pose_covariance;

    // imu协方差参数
    double gyr_cov, acc_cov, b_gyr_cov, b_acc_cov;
    // 坐标系变换
    geometry_msgs::msg::TransformStamped tf_i_l; // lidar到imu的坐标系变换
    geometry_msgs::msg::TransformStamped tf_g_l; // lidar到gnss的坐标系变换
    // lidar在world系中的位姿
    geometry_msgs::msg::PoseWithCovarianceStamped pose_w_l_msg_with_stamp;
    // 激光雷达到imu的外参
    V3D Lidar_T_wrt_IMU;
    M3D Lidar_R_wrt_IMU;

    // 使用VGICP
#ifdef USE_VGICP_CUDA
    std::shared_ptr<fast_gicp::FastVGICPCuda<PointSource, PointTarget>> registration_ptr;
#else
    std::shared_ptr<fast_gicp::FastVGICP<PointSource, PointTarget>> registration_ptr;
#endif
    // VGICP参数
    float vgicp_resolution;
    int vgicp_num_threads;
    // 构建增量局部地图树
#ifdef USE_IVOX
// ivox
#ifdef IVOX_NODE_TYPE_PHC
    using IVoxType = IVox<3, IVoxNodeType::PHC, Point_XYZI>;
#else
    using IVoxType = IVox<3, IVoxNodeType::DEFAULT, Point_XYZI>;
#endif
    IVoxType::Options ivox_options;
    std::shared_ptr<IVoxType> p_ivox = nullptr;
    std::vector<IVoxType::PointVector> nearest_point_set;
    bool FIRST_BUILD_INCREMENTAL_MAP;
#endif

#ifdef USE_IKDTREE
    std::vector<KD_TREE<Point_XYZI>::PointVector> nearest_point_set; // 最近点集合
    BoxPointType LocalMap_Points;                    // ikd-tree中，局部地图包围角点
     KD_TREE<Point_XYZI> ikdtree_local_map;
#endif

    pcl::KdTreeFLANN<Point_XYZ> kdtree_3dPose;
    std::map<int, PointCloud_XYZI> local_key_frames; // world系下的关键帧集合

    // hyper-parameters
    // 订阅发布话题
    std::string sub_lidar_topic;       // 激光雷达点云话题
    std::string sub_imu_topic;       // imu话题
    std::string sub_gnss_pose_topic; // gnss话题

    std::string pub_lidar_pose_topic; // 激光雷达位姿话题

    // 坐标系名称
    std::string imu_coor_sys;
    std::string lidar_coor_sys;
    std::string world_coor_sys;
    std::string gnss_coor_sys;

    PointCloud_XYZRPYI key_6dPoses; // 关键帧6d位姿
    PointCloud_XYZ::Ptr key_3dPoses;          // 关键帧6d位姿

    esekfom::esekf<state_ikfom, 12, input_ikfom> eskf; // 状态，噪声维度，输入
    state_ikfom state_variable;                        // 状态量

    std::shared_ptr<ImuProcess> p_imu;   // IMU数据预处理类
    std::vector<double> extrinsic_T_L_I; // 雷达相对于IMU的外参T
    std::vector<double> extrinsic_R_L_I; // 雷达相对于IMU的外参R

    // 订阅发布话题
    rclcpp::Subscription<sensor_msgs::msg::PointCloud2>::SharedPtr sub_pcl; // 订阅激光雷达点云
    rclcpp::Subscription<sensor_msgs::msg::Imu>::SharedPtr sub_imu;         // 订阅imu数据
    rclcpp::Subscription<geometry_msgs::msg::PoseWithCovarianceStamped>::SharedPtr sub_gnss_pose;

    rclcpp::Publisher<geometry_msgs::msg::PoseWithCovarianceStamped>::SharedPtr pub_lidar_pose; // 发布初始位姿

    // test
    rclcpp::Publisher<sensor_msgs::msg::PointCloud2>::SharedPtr pub_cloud;
    rclcpp::Publisher<sensor_msgs::msg::PointCloud2>::SharedPtr pub_lidar;
    rclcpp::Publisher<sensor_msgs::msg::PointCloud2>::SharedPtr pub_local_map;

private:
    // 回调函数
    void gnss_pose_callback(const geometry_msgs::msg::PoseWithCovarianceStamped &_gnss_msg);
    void pcl_callback(const sensor_msgs::msg::PointCloud2 &_pcl_msg);
    void imu_callback(const sensor_msgs::msg::Imu &_imu_msg);

    // 数据同步
    bool data_synchronization(MeasureGroup &meas);

    // 加载关键帧位姿文件
    void load_key_pose_file();

    // 构建局部增量地图
    void build_local_incremental_map(geometry_msgs::msg::Pose &_pose);
    // 观测模型
    void h_share_model(state_ikfom &state_variable, esekfom::dyn_share_datastruct<double> &ekfom_data);
    // 得到坐标系之间的变换
    bool get_tf(std::string target_frame, std::string source_frame, geometry_msgs::msg::TransformStamped &transform_stamped);
    // 得到推测的lidar在world系下的位置
    geometry_msgs::msg::Pose get_infer_position(geometry_msgs::msg::TransformStamped &transform_stamped, geometry_msgs::msg::PoseWithCovarianceStamped &gnss_pose_with_stamp);
    // 点云变换
    PointCloud_XYZI transformPointCloud(PointCloud_XYZI &cloudIn, Point_XYZRPY &transformIn);
    PointCloud_XYZ transformPointCloud(PointCloud_XYZ &cloudIn, Point_XYZRPY &transformIn);
};

#endif
