#include "gnss_localizer/geographicLib.hpp"

double EllipsoidHeight2OrthometricHeight(
  const sensor_msgs::msg::NavSatFix & nav_sat_fix_msg, const rclcpp::Logger & logger)
{
  double OrthometricHeight{0.0};
  try {
    GeographicLib::Geoid egm2008("egm2008-1");
    OrthometricHeight = egm2008.ConvertHeight(
      nav_sat_fix_msg.latitude, nav_sat_fix_msg.longitude, nav_sat_fix_msg.altitude,
      GeographicLib::Geoid::ELLIPSOIDTOGEOID);
  } catch (const GeographicLib::GeographicErr & err) {
    RCLCPP_ERROR_STREAM(
      logger, "Failed to convert Height from Ellipsoid to Orthometric" << err.what());
  }
  return OrthometricHeight;
}
GNSSStat NavSatFix2LocalCartesianWGS84(
  const sensor_msgs::msg::NavSatFix & nav_sat_fix_msg,
  sensor_msgs::msg::NavSatFix nav_sat_fix_origin_, const rclcpp::Logger & logger)
{
  GNSSStat local_cartesian;
  local_cartesian.coordinate_system = CoordinateSystem::LOCAL_CARTESIAN_WGS84;

  try {
    GeographicLib::LocalCartesian localCartesian_origin(
      nav_sat_fix_origin_.latitude, nav_sat_fix_origin_.longitude, nav_sat_fix_origin_.altitude);
    localCartesian_origin.Forward(
      nav_sat_fix_msg.latitude, nav_sat_fix_msg.longitude, nav_sat_fix_msg.altitude,
      local_cartesian.x, local_cartesian.y, local_cartesian.z);

    local_cartesian.latitude = nav_sat_fix_msg.latitude;
    local_cartesian.longitude = nav_sat_fix_msg.longitude;
    local_cartesian.altitude = nav_sat_fix_msg.altitude;

    local_cartesian.position_covariance_x=nav_sat_fix_msg.position_covariance[0];
    local_cartesian.position_covariance_y=nav_sat_fix_msg.position_covariance[4];
    local_cartesian.position_covariance_z=nav_sat_fix_msg.position_covariance[8];

  } catch (const GeographicLib::GeographicErr & err) {
    RCLCPP_ERROR_STREAM(logger, "Failed to convert NavSatFix to LocalCartesian" << err.what());
  }
  return local_cartesian;
}
GNSSStat NavSatFix2UTM(
  const sensor_msgs::msg::NavSatFix & nav_sat_fix_msg, const rclcpp::Logger & logger)
{
  GNSSStat utm;
  utm.coordinate_system = CoordinateSystem::UTM;

  try {
    GeographicLib::UTMUPS::Forward(
      nav_sat_fix_msg.latitude, nav_sat_fix_msg.longitude, utm.zone, utm.northup, utm.x, utm.y);

    utm.z = EllipsoidHeight2OrthometricHeight(nav_sat_fix_msg, logger);

    utm.latitude = nav_sat_fix_msg.latitude;
    utm.longitude = nav_sat_fix_msg.longitude;
    utm.altitude = nav_sat_fix_msg.altitude;

    utm.position_covariance_x=nav_sat_fix_msg.position_covariance[0];
    utm.position_covariance_y=nav_sat_fix_msg.position_covariance[0];
    utm.position_covariance_z=nav_sat_fix_msg.position_covariance[0];
  } catch (const GeographicLib::GeographicErr & err) {
    RCLCPP_ERROR_STREAM(logger, "Failed to convert from LLH to UTM" << err.what());
  }
  return utm;
}
GNSSStat NavSatFix2LocalCartesianUTM(
  const sensor_msgs::msg::NavSatFix & nav_sat_fix_msg,
  sensor_msgs::msg::NavSatFix nav_sat_fix_origin, const rclcpp::Logger & logger)
{
  GNSSStat utm_local;
  utm_local.coordinate_system = CoordinateSystem::UTM;
  try {
    // origin of the local coordinate system in global frame
    GNSSStat utm_origin;
    utm_origin.coordinate_system = CoordinateSystem::UTM;
    GeographicLib::UTMUPS::Forward(
      nav_sat_fix_origin.latitude, nav_sat_fix_origin.longitude, utm_origin.zone,
      utm_origin.northup, utm_origin.x, utm_origin.y);
    utm_origin.z = EllipsoidHeight2OrthometricHeight(nav_sat_fix_origin, logger);
    // individual coordinates of global coordinate system
    double global_x = 0.0;
    double global_y = 0.0;
    GeographicLib::UTMUPS::Forward(
      nav_sat_fix_msg.latitude, nav_sat_fix_msg.longitude, utm_origin.zone, utm_origin.northup,
      global_x, global_y);
    utm_local.latitude = nav_sat_fix_msg.latitude;
    utm_local.longitude = nav_sat_fix_msg.longitude;
    utm_local.altitude = nav_sat_fix_msg.altitude;
    // individual coordinates of local coordinate system
    utm_local.x = global_x - utm_origin.x;
    utm_local.y = global_y - utm_origin.y;
    utm_local.z = EllipsoidHeight2OrthometricHeight(nav_sat_fix_msg, logger) - utm_origin.z;

    utm_local.position_covariance_x=nav_sat_fix_msg.position_covariance[0];
    utm_local.position_covariance_y=nav_sat_fix_msg.position_covariance[0];
    utm_local.position_covariance_z=nav_sat_fix_msg.position_covariance[0];
  } catch (const GeographicLib::GeographicErr & err) {
    RCLCPP_ERROR_STREAM(
      logger, "Failed to convert from LLH to UTM in local coordinates" << err.what());
  }
  return utm_local;
}
GNSSStat UTM2MGRS(
  const GNSSStat & utm, const MGRSPrecision & precision, const rclcpp::Logger & logger)
{
  constexpr int GZD_ID_size = 5;  // size of header like "53SPU"

  GNSSStat mgrs = utm;
  mgrs.coordinate_system = CoordinateSystem::MGRS;
  try {
    std::string mgrs_code;
    GeographicLib::MGRS::Forward(
        utm.zone, utm.northup, utm.x, utm.y, utm.latitude, static_cast<int>(precision), mgrs_code);
    mgrs.zone = std::stod(mgrs_code.substr(0, GZD_ID_size));
    mgrs.x = std::stod(mgrs_code.substr(GZD_ID_size, static_cast<int>(precision))) *
             std::pow(
               10, static_cast<int>(MGRSPrecision::_1_METER) -
                     static_cast<int>(precision));  // set unit as [m]
    mgrs.y = std::stod(mgrs_code.substr(
               GZD_ID_size + static_cast<int>(precision), static_cast<int>(precision))) *
             std::pow(
               10, static_cast<int>(MGRSPrecision::_1_METER) -
                     static_cast<int>(precision));  // set unit as [m]
    mgrs.z = utm.z;                                 // TODO(ryo.watanabe)

  } catch (const GeographicLib::GeographicErr & err) {
    RCLCPP_ERROR_STREAM(logger, "Failed to convert from UTM to MGRS" << err.what());
  }
  return mgrs;
}

GNSSStat NavSatFix2MGRS(
  const sensor_msgs::msg::NavSatFix & nav_sat_fix_msg, const MGRSPrecision & precision,
  const rclcpp::Logger & logger)
{
  const auto utm = NavSatFix2UTM(nav_sat_fix_msg, logger);
  const auto mgrs = UTM2MGRS(utm, precision, logger);
  return mgrs;
}

GNSSStat GPSConverter(
  const sensor_msgs::msg::NavSatFix & nav_sat_fix_msg, CoordinateSystem coordinate_system)
{
  GNSSStat gnss_stat;
  if (coordinate_system == CoordinateSystem::UTM) {
    gnss_stat = NavSatFix2UTM(nav_sat_fix_msg, get_logger("rclcpp"));
  } else if (coordinate_system == CoordinateSystem::LOCAL_CARTESIAN_UTM) {
    sensor_msgs::msg::NavSatFix nav_sat_fix_origin_;
    nav_sat_fix_origin_.latitude = 0.0;
    nav_sat_fix_origin_.longitude = 0.0;
    nav_sat_fix_origin_.altitude = 0.0;
    gnss_stat =NavSatFix2LocalCartesianUTM(nav_sat_fix_msg, nav_sat_fix_origin_, get_logger("rclcpp"));
  } else if (coordinate_system == CoordinateSystem::MGRS) {
    gnss_stat = NavSatFix2MGRS(nav_sat_fix_msg, MGRSPrecision::_100MICRO_METER, get_logger("rclcpp"));
  }else if (coordinate_system == CoordinateSystem::LOCAL_CARTESIAN_WGS84) {
    sensor_msgs::msg::NavSatFix nav_sat_fix_origin_;
    nav_sat_fix_origin_.latitude = 0.0;
    nav_sat_fix_origin_.longitude = 0.0;
    nav_sat_fix_origin_.altitude = 0.0;
    gnss_stat =NavSatFix2LocalCartesianWGS84(nav_sat_fix_msg, nav_sat_fix_origin_, get_logger("rclcpp"));
  } else {
    // RCLCPP_ERROR_STREAM_THROTTLE(
    //   get_logger("rclcpp"), get_clock(), std::chrono::milliseconds(1000).count(),
    //   "Unknown Coordinate System");
  }
  return gnss_stat;
}
