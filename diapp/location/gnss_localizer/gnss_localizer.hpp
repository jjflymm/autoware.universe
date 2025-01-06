#ifndef SENSOR_GNSS_LOCALIZER
#define SENSOR_GNSS_LOCALIZER

// ros2
#include <rclcpp/rclcpp.hpp>
#include <tf2/transform_datatypes.h>
#include <tf2/LinearMath/Quaternion.h>
#include <tf2/LinearMath/Transform.h>
#include <tf2_ros/transform_broadcaster.h>
#include <tf2_ros/transform_listener.h>
#include <tf2_ros/buffer.h>
#include <geometry_msgs/msg/transform_stamped.hpp>
#include <sensor_msgs/msg/nav_sat_fix.hpp>
#include <geometry_msgs/msg/quaternion_stamped.hpp>
#include <geometry_msgs/msg/pose_with_covariance_stamped.hpp>
#include "gnss_localizer/geographicLib.hpp"
#include <tf2_geometry_msgs/tf2_geometry_msgs.hpp>
// std c++
#include <deque>

static const unsigned int BUFFER_SIZE = 10; // 缓冲器大小
static const double ZERO = 1e-5;            // 零距离
static const double PI_2 = 1.5708;

class gnss_localizer : public rclcpp::Node
{
public:
    gnss_localizer(std::string node_name, const rclcpp::NodeOptions &options);

private:
    /*********************变量****************************/
    double gnss_compensation_time;
    std::string world_coordinate_system; // MGRS UTM

    // 话题
    std::string sub_gnss_topic;
    std::string sub_course_topic;

    std::string pub_gnss_pose_topic;
    
    bool b_translation;     // 是否需要移动gnss原点
    bool b_use_orientation; // 是否需要使用gnss的方位角

    std::deque<GNSSStat> gnss_deque_buffer;                             // gnss队列
    std::deque<geometry_msgs::msg::Quaternion> quaternion_deque_buffer; // gnss四元数队列

    // 参考经纬度
    double refer_latitude;
    double refer_longitude;
    double refer_altitude;

    // 坐标系名称
    std::string gnss_coor_sys;
    std::string world_coor_sys;

    tf2_ros::TransformBroadcaster tf_broadcaster; // 坐标系广播器

    tf2_ros::Buffer tf_buffer;
    tf2_ros::TransformListener tf_listener; // 坐标系监听器

    geometry_msgs::msg::QuaternionStamped course_msg; // gnss方向角信息

    rclcpp::Subscription<sensor_msgs::msg::NavSatFix>::SharedPtr sub_gnss;             // 订阅gnss经纬度坐标
    rclcpp::Subscription<geometry_msgs::msg::QuaternionStamped>::SharedPtr sub_course; // 订阅航向

    rclcpp::Publisher<geometry_msgs::msg::PoseWithCovarianceStamped>::SharedPtr pub_gnss_pose;  // 发布gnss在world坐标系下的位姿
private:
    GNSSStat convert(const sensor_msgs::msg::NavSatFix &gnss, std::string _coordinate_system); // 把经纬度转换成MGRS,UTM等坐标系下的坐标
    geometry_msgs::msg::Quaternion calc_orientation(std::deque<GNSSStat> &_gnss_deque);        // 通过gnss坐标系信息，计算gnss方向角
    void gnss_callback(const sensor_msgs::msg::NavSatFix &gnss);                               // gnss回调函数
    void gnss_course_callback(const geometry_msgs::msg::QuaternionStamped &course);            // gnss方向角回调函数
};

#endif
