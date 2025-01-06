#include "gnss_localizer/gnss_localizer.hpp"

gnss_localizer::gnss_localizer(std::string node_name, const rclcpp::NodeOptions &options) : rclcpp::Node(node_name, options),
                                                                                            tf_buffer(this->get_clock()),
                                                                                            tf_listener(tf_buffer),
                                                                                            tf_broadcaster(*this)
{
  this->declare_parameter("gnss_compensation_time", -0.144896); // lidar时间补偿
  this->get_parameter("gnss_compensation_time", gnss_compensation_time);

  this->declare_parameter("world_coordinate_system", "MGRS"); // 全球坐标系统
  this->get_parameter("world_coordinate_system", world_coordinate_system);

  this->declare_parameter("sub_gnss_topic", "/sensing/gnss/diapp_gnss_ms6111_node/nav_sat_fix"); // 订阅gnss ins话题
  this->get_parameter("sub_gnss_topic", sub_gnss_topic);

  this->declare_parameter("sub_course_topic", "/sensing/gnss/diapp_orientation"); // 订阅gnss course话题
  this->get_parameter("sub_course_topic", sub_course_topic);

  this->declare_parameter("pub_gnss_pose_topic", "/location/gnss/pose"); // 发布由gnss
  this->get_parameter("pub_gnss_pose_topic", pub_gnss_pose_topic);

  this->declare_parameter("gnss_coor_sys", "gnss_link"); // gnss坐标系
  this->get_parameter("gnss_coor_sys", gnss_coor_sys);

  this->declare_parameter("world_coor_sys", "map"); // world坐标系
  this->get_parameter("world_coor_sys", world_coor_sys);

  this->declare_parameter("b_translation", true); // 是否需要平移
  this->get_parameter("b_translation", b_translation);

  this->declare_parameter("b_use_orientation", false); // 是否需要平移
  this->get_parameter("b_use_orientation", b_use_orientation);

  this->declare_parameter("refer_latitude", 22.67916456206); // 参考维度
  this->get_parameter("refer_latitude", refer_latitude);

  this->declare_parameter("refer_longitude", 114.3549381188); // 参考经度
  this->get_parameter("refer_longitude", refer_longitude);

  this->declare_parameter("refer_altitude", 51.2127); // 参考高程
  this->get_parameter("refer_altitude", refer_altitude);

  sub_gnss = this->create_subscription<sensor_msgs::msg::NavSatFix>(sub_gnss_topic, 10, std::bind(&gnss_localizer::gnss_callback, this, std::placeholders::_1));
  sub_course = this->create_subscription<geometry_msgs::msg::QuaternionStamped>(sub_course_topic, 10, std::bind(&gnss_localizer::gnss_course_callback, this, std::placeholders::_1));

  pub_gnss_pose = this->create_publisher<geometry_msgs::msg::PoseWithCovarianceStamped>(pub_gnss_pose_topic, 1);
}

void gnss_localizer::gnss_callback(const sensor_msgs::msg::NavSatFix &gnss)
{
  geometry_msgs::msg::PoseWithCovarianceStamped gnss_antenna_pose;

  if (gnss.status.status < sensor_msgs::msg::NavSatStatus::STATUS_FIX)
    return;

  static rclcpp::Time last_gnss_timestamp = rclcpp::Time(0);
  rclcpp::Time curr_gnss_timestamp = rclcpp::Time(gnss.header.stamp.sec * 1e9 + gnss.header.stamp.nanosec + gnss_compensation_time * 1e9);

  if (curr_gnss_timestamp <= last_gnss_timestamp)
  {
    RCLCPP_WARN(this->get_logger(), "gnss pose loop back, clear buffer");
    return;
  }
  last_gnss_timestamp = curr_gnss_timestamp;

  double gnss_trans_x = 0.0, gnss_trans_y = 0.0, gnss_trans_z = 0.0;
  if (b_translation)
  {
    sensor_msgs::msg::NavSatFix gnss_trans;
    gnss_trans.latitude = refer_latitude;
    gnss_trans.longitude = refer_longitude;
    gnss_trans.altitude = refer_altitude;

    auto gnss_trans_stat = convert(gnss_trans, world_coordinate_system);
    gnss_trans_x = gnss_trans_stat.x;
    gnss_trans_y = gnss_trans_stat.y;
    gnss_trans_z = gnss_trans_stat.z;
  }
  auto gnss_stat = convert(gnss, world_coordinate_system);

  gnss_stat.x -= gnss_trans_x;
  gnss_stat.y -= gnss_trans_y;
  gnss_stat.z -= gnss_trans_z;

  if (b_use_orientation)
    gnss_antenna_pose.pose.pose.orientation = course_msg.quaternion;
  else
  {
    if (gnss_deque_buffer.size() == BUFFER_SIZE)
      gnss_deque_buffer.pop_front();
    gnss_deque_buffer.push_back(gnss_stat);
    if (gnss_deque_buffer.size() < BUFFER_SIZE)
      return;
    gnss_antenna_pose.pose.pose.orientation = calc_orientation(gnss_deque_buffer);
  }

  gnss_antenna_pose.header.stamp = curr_gnss_timestamp;
  gnss_antenna_pose.header.frame_id = world_coor_sys;
  gnss_antenna_pose.pose.pose.position.x = gnss_stat.x;
  gnss_antenna_pose.pose.pose.position.y = gnss_stat.y;
  gnss_antenna_pose.pose.pose.position.z = gnss_stat.z;

  gnss_antenna_pose.pose.covariance[7 * 0] = gnss.position_covariance[0] > 0.0 ? gnss.position_covariance[0] : 2.0;
  gnss_antenna_pose.pose.covariance[7 * 1] = gnss.position_covariance[4] > 0.0 ? gnss.position_covariance[4] : 2.0;
  gnss_antenna_pose.pose.covariance[7 * 2] = gnss.position_covariance[8] > 0.0 ? gnss.position_covariance[8] : 2.0;

  gnss_antenna_pose.pose.covariance[7 * 3] = 0.1;
  gnss_antenna_pose.pose.covariance[7 * 4] = 0.1;
  gnss_antenna_pose.pose.covariance[7 * 5] = 1.0;

  pub_gnss_pose->publish(gnss_antenna_pose);
  /************************发布gnss在world系下的坐标变换***************************/
  geometry_msgs::msg::TransformStamped transform_stamped;
  transform_stamped.header.frame_id = world_coor_sys;
  transform_stamped.child_frame_id = "gnss_base_link";
  transform_stamped.header.stamp = curr_gnss_timestamp;

  transform_stamped.transform.translation.x = gnss_antenna_pose.pose.pose.position.x;
  transform_stamped.transform.translation.y = gnss_antenna_pose.pose.pose.position.y;
  transform_stamped.transform.translation.z = gnss_antenna_pose.pose.pose.position.z;

  tf2::Quaternion tf_quaternion;
  tf2::fromMsg(gnss_antenna_pose.pose.pose.orientation, tf_quaternion);
  transform_stamped.transform.rotation.x = tf_quaternion.x();
  transform_stamped.transform.rotation.y = tf_quaternion.y();
  transform_stamped.transform.rotation.z = tf_quaternion.z();
  transform_stamped.transform.rotation.w = tf_quaternion.w();
  tf_broadcaster.sendTransform(transform_stamped);
}

GNSSStat gnss_localizer::convert(const sensor_msgs::msg::NavSatFix &gnss, std::string _coordinate_system)
{
  GNSSStat gnss_stat;

  if (_coordinate_system == "MGRS")
    gnss_stat = GPSConverter(gnss, CoordinateSystem::MGRS);
  else if (_coordinate_system == "UTM")
    gnss_stat = GPSConverter(gnss, CoordinateSystem::UTM);
  else
    RCLCPP_ERROR(this->get_logger(), "please chooose right coordinate system,eg. UTM or MGRS");

  return gnss_stat;
}

geometry_msgs::msg::Quaternion gnss_localizer::calc_orientation(std::deque<GNSSStat> &_gnss_deque)
{
  GNSSStat front_middle_position; // 前半中心位置
  GNSSStat rear_middle_position;  // 后半中心位置

  int middle_position_index = std::floor(_gnss_deque.size() / 2);
  // 计算前半队列中心位置
  for (int i = 0; i < middle_position_index; i++)
  {
    front_middle_position.x += _gnss_deque[i].x;
    front_middle_position.y += _gnss_deque[i].y;
  }
  front_middle_position.x /= (double)middle_position_index;
  front_middle_position.y /= (double)middle_position_index;
  // 计算后半队列中心位置
  for (int i = middle_position_index; i < _gnss_deque.size(); i++)
  {
    rear_middle_position.x += _gnss_deque[i].x;
    rear_middle_position.y += _gnss_deque[i].y;
  }

  double dividend = _gnss_deque.size() - middle_position_index;
  rear_middle_position.x /= dividend;
  rear_middle_position.y /= dividend;

  // 计算方向角
  double x_diff = rear_middle_position.x - front_middle_position.x;
  double y_diff = rear_middle_position.y - front_middle_position.y;
  // 判断gnss是否静止
  if (quaternion_deque_buffer.size() != 0)
    if (fabs(x_diff) <= ZERO && fabs(y_diff) <= ZERO)
      return quaternion_deque_buffer.back();
  double yaw = -PI_2;
  if (x_diff == 0 && y_diff == 0)
    yaw = -PI_2;
  else
    yaw = atan2(y_diff, x_diff) - PI_2;
  // rpy转四元数
  geometry_msgs::msg::Quaternion quaternion_msg;
  tf2::Quaternion tf_quar;
  tf_quar.setRPY(0, 0, yaw);
  tf2::convert(tf_quar, quaternion_msg);
  // 填充四元数队列
  if (quaternion_deque_buffer.size() == BUFFER_SIZE)
    quaternion_deque_buffer.pop_front();
  quaternion_deque_buffer.push_back(quaternion_msg);
  return quaternion_msg;
}

void gnss_localizer::gnss_course_callback(const geometry_msgs::msg::QuaternionStamped &course)
{
  course_msg = course;
}

int main(int argc, char **argv)
{
  rclcpp::init(argc, argv);

  rclcpp::NodeOptions options;
  options.use_intra_process_comms(true);
  rclcpp::executors::SingleThreadedExecutor gnss_localizer_exe;
  auto gnss_localizer_node = std::make_shared<gnss_localizer>("gnss_localizer", options);
  gnss_localizer_exe.add_node(gnss_localizer_node);

  gnss_localizer_exe.spin();
  rclcpp::shutdown();

  return 0;
}
