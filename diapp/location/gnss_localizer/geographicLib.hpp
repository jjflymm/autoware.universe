#pragma once
/*use GeographicLib*/
#include <GeographicLib/Geoid.hpp>
#include <GeographicLib/LocalCartesian.hpp>
#include <GeographicLib/MGRS.hpp>
#include <GeographicLib/UTMUPS.hpp>
/*use ros2*/
#include <rclcpp/rclcpp.hpp>
#include <sensor_msgs/msg/nav_sat_fix.hpp>
#include <std_msgs/msg/header.hpp>

using namespace rclcpp;

enum class CoordinateSystem
{
  UTM = 0,  //通用横轴墨卡托投影坐标系。
  MGRS = 1,   //军事网格参考系统。
  LOCAL_CARTESIAN_WGS84 = 2,  //基于 WGS84 椭球体的局部笛卡尔坐标系。
  LOCAL_CARTESIAN_UTM = 3     //基于 UTM 坐标系的局部笛卡尔坐标系。
};

struct GNSSStat
{
  CoordinateSystem coordinate_system;  //使用的坐标系
  bool northup;  //示 UTM 坐标是否位于北半球。
  int zone;   //表示 UTM 坐标的区域编号。
  double x;
  double y;
  double z;
  double latitude;   //纬度
  double longitude;  //经度
  double altitude;   //高度
  double position_covariance_x;   //位置协方差
  double position_covariance_y;
  double position_covariance_z;

  GNSSStat()
  {
    x = 0.0;
    y = 0.0;
    z = 0.0;
    latitude = 0.0;
    longitude = 0.0;
    altitude = 0.0;
    position_covariance_x = 0.0;
    position_covariance_y = 0.0;
    position_covariance_z = 0.0;
    coordinate_system = CoordinateSystem::MGRS;
  }
};

enum class MGRSPrecision //军事网格参考系统
{
  _10_KIRO_METER = 1,
  _1_KIRO_METER = 2,
  _100_METER = 3,
  _10_METER = 4,
  _1_METER = 5,
  _100_MIllI_METER = 6,
  _10_MIllI_METER = 7,
  _1_MIllI_METER = 8,
  _100MICRO_METER = 9,
};

double EllipsoidHeight2OrthometricHeight(const sensor_msgs::msg::NavSatFix &nav_sat_fix_msg, const rclcpp::Logger &logger);  //将椭球高（Ellipsoid Height）转换为正高（Orthometric Height）

//将 NavSatFix 消息转换为基于 WGS84 的局部笛卡尔坐标系。
GNSSStat NavSatFix2LocalCartesianWGS84(const sensor_msgs::msg::NavSatFix &nav_sat_fix_msg, sensor_msgs::msg::NavSatFix nav_sat_fix_origin_, const rclcpp::Logger &logger);

//将 NavSatFix 消息转换为 UTM 坐标。
GNSSStat NavSatFix2UTM(const sensor_msgs::msg::NavSatFix &nav_sat_fix_msg, const rclcpp::Logger &logger);

//将 NavSatFix 消息转换为基于 UTM 的局部笛卡尔坐标系。
GNSSStat NavSatFix2LocalCartesianUTM(const sensor_msgs::msg::NavSatFix &nav_sat_fix_msg, sensor_msgs::msg::NavSatFix nav_sat_fix_origin, const rclcpp::Logger &logger);

//将 UTM 坐标转换为 MGRS 坐标。
GNSSStat UTM2MGRS(const GNSSStat &utm, const MGRSPrecision &precision, const rclcpp::Logger &logger);

//将 NavSatFix 消息直接转换为 MGRS 坐标。
GNSSStat NavSatFix2MGRS(const sensor_msgs::msg::NavSatFix &nav_sat_fix_msg, const MGRSPrecision &precision, const rclcpp::Logger &logger);

//根据指定的坐标系，将 NavSatFix 消息转换为目标坐标系。
GNSSStat GPSConverter(const sensor_msgs::msg::NavSatFix &nav_sat_fix_msg, CoordinateSystem coordinate_system);
