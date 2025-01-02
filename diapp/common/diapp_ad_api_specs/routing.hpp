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

#ifndef DIAPP_AD_API_SPECS__ROUTING_HPP_
#define DIAPP_AD_API_SPECS__ROUTING_HPP_

#include <rclcpp/qos.hpp>

#include <diapp_adapi_msgs/msg/route.hpp>
#include <diapp_adapi_msgs/msg/route_state.hpp>
#include <diapp_adapi_msgs/srv/clear_route.hpp>
#include <diapp_adapi_msgs/srv/set_route.hpp>
#include <diapp_adapi_msgs/srv/set_route_points.hpp>

namespace diapp_ad_api::routing
{

struct SetRoutePoints
{
  using Service = diapp_adapi_msgs::srv::SetRoutePoints;
  static constexpr char name[] = "/api/routing/set_route_points";
};

struct SetRoute
{
  using Service = diapp_adapi_msgs::srv::SetRoute;
  static constexpr char name[] = "/api/routing/set_route";
};

struct ChangeRoutePoints
{
  using Service = diapp_adapi_msgs::srv::SetRoutePoints;
  static constexpr char name[] = "/api/routing/change_route_points";
};

struct ChangeRoute
{
  using Service = diapp_adapi_msgs::srv::SetRoute;
  static constexpr char name[] = "/api/routing/change_route";
};

struct ClearRoute
{
  using Service = diapp_adapi_msgs::srv::ClearRoute;
  static constexpr char name[] = "/api/routing/clear_route";
};

struct RouteState
{
  using Message = diapp_adapi_msgs::msg::RouteState;
  static constexpr char name[] = "/api/routing/state";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

struct Route
{
  using Message = diapp_adapi_msgs::msg::Route;
  static constexpr char name[] = "/api/routing/route";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

}  // namespace diapp_ad_api::routing

#endif  // DIAPP_AD_API_SPECS__ROUTING_HPP_
