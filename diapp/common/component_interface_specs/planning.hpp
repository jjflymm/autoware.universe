// Copyright 2022 TIER IV, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef COMPONENT_INTERFACE_SPECS__PLANNING_HPP_
#define COMPONENT_INTERFACE_SPECS__PLANNING_HPP_

#include <rclcpp/qos.hpp>

#include <diapp_adapi_msgs/msg/route_state.hpp>
#include <diapp_adapi_msgs/srv/clear_route.hpp>
#include <diapp_adapi_msgs/srv/set_route.hpp>
#include <diapp_adapi_msgs/srv/set_route_points.hpp>
#include <diapp_planning_msgs/msg/trajectory.hpp>
#include <diapp_planning_msgs/msg/lanelet_route.hpp>

namespace planning_interface
{

struct SetRoutePoints  //用于设置路径点（Route Points）的服务
{
  using Service = diapp_adapi_msgs::srv::SetRoutePoints;
  static constexpr char name[] = "/planning/mission_planning/set_route_points";
};

struct SetRoute  //用于设置完整路径（Route）的服务
{
  using Service = diapp_adapi_msgs::srv::SetRoute;
  static constexpr char name[] = "/planning/mission_planning/set_route";
};

struct ChangeRoutePoints  //用于修改路径点（Route Points）的服务
{
  using Service = diapp_adapi_msgs::srv::SetRoutePoints;
  static constexpr char name[] = "/planning/mission_planning/change_route_points";
};

struct ChangeRoute  //用于修改完整路径（Route）的服务
{
  using Service = diapp_adapi_msgs::srv::SetRoute;
  static constexpr char name[] = "/planning/mission_planning/change_route";
};

struct ClearRoute  //用于清除当前路径（Route）的服务
{
  using Service = diapp_adapi_msgs::srv::ClearRoute;
  static constexpr char name[] = "/planning/mission_planning/clear_route";
};

struct RouteState  //用于获取路径状态（Route State）的主题。通过订阅该主题，可以实时监控路径的状态（如是否已设置、是否有效等）
{
  using Message = diapp_adapi_msgs::msg::RouteState;
  static constexpr char name[] = "/planning/mission_planning/route_state";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

struct Route   //获取当前路径（Route）的主题
{
  using Message = diapp_planning_msgs::msg::LaneletRoute;
  static constexpr char name[] = "/planning/mission_planning/route";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

struct NormalRoute   //用于获取正常路径（Normal Route）的主题
{
  using Message = diapp_planning_msgs::msg::LaneletRoute;
  static constexpr char name[] = "/planning/mission_planning/normal_route";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

struct MrmRoute   //用于获取应急路径（MRM Route，Minimum Risk Maneuver Route）的主题。通过订阅该主题，可以获取车辆在应急模式下的行驶路径。
{
  using Message = diapp_planning_msgs::msg::LaneletRoute;
  static constexpr char name[] = "/planning/mission_planning/mrm_route";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

struct Trajectory   //用于获取规划轨迹（Trajectory）的主题。通过订阅该主题，可以实时获取车辆的规划行驶轨迹。
{
  using Message = diapp_planning_msgs::msg::Trajectory;
  static constexpr char name[] = "/planning/scenario_planning/trajectory";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_VOLATILE;
};

}  // namespace planning_interface

#endif  // COMPONENT_INTERFACE_SPECS__PLANNING_HPP_
