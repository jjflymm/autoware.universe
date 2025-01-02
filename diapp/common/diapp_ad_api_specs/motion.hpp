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

#ifndef DIAPP_AD_API_SPECS__MOTION_HPP_
#define DIAPP_AD_API_SPECS__MOTION_HPP_

#include <rclcpp/qos.hpp>

#include <diapp_adapi_msgs/msg/motion_state.hpp>
#include <diapp_adapi_msgs/srv/accept_start.hpp>

namespace diapp_ad_api::motion
{

struct AcceptStart
{
  using Service = diapp_adapi_msgs::srv::AcceptStart;
  static constexpr char name[] = "/api/motion/accept_start";
};

struct State
{
  using Message = diapp_adapi_msgs::msg::MotionState;
  static constexpr char name[] = "/api/motion/state";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

}  // namespace diapp_ad_api::motion

#endif  // DIAPP_AD_API_SPECS__MOTION_HPP_
