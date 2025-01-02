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

#ifndef DIAPP_AD_API_SPECS__OPERATION_MODE_HPP_
#define DIAPP_AD_API_SPECS__OPERATION_MODE_HPP_

#include <rclcpp/qos.hpp>

#include <diapp_adapi_msgs/msg/operation_mode_state.hpp>
#include <diapp_adapi_msgs/srv/change_operation_mode.hpp>

namespace diapp_ad_api::operation_mode
{

struct ChangeToStop  //定义切换到 停止模式 的服务。
{
  using Service = diapp_adapi_msgs::srv::ChangeOperationMode;
  static constexpr char name[] = "/api/operation_mode/change_to_stop";
};

struct ChangeToAutonomous   //定义切换到 自动驾驶模式 的服务。
{
  using Service = diapp_adapi_msgs::srv::ChangeOperationMode;
  static constexpr char name[] = "/api/operation_mode/change_to_autonomous";
};

struct ChangeToLocal   //定义切换到 本地模式 的服务。
{
  using Service = diapp_adapi_msgs::srv::ChangeOperationMode;
  static constexpr char name[] = "/api/operation_mode/change_to_local";
};

struct ChangeToRemote  //定义切换到 远程模式 的服务。
{
  using Service = diapp_adapi_msgs::srv::ChangeOperationMode;
  static constexpr char name[] = "/api/operation_mode/change_to_remote";
};

struct EnableDiappControl   //定义 启用 Diapp 控制 的服务。
{
  using Service = diapp_adapi_msgs::srv::ChangeOperationMode;
  static constexpr char name[] = "/api/operation_mode/enable_diapp_control";
};
   
struct DisableDiappControl   //定义 禁用 Diapp 控制 的服务。
{
  using Service = diapp_adapi_msgs::srv::ChangeOperationMode;
  static constexpr char name[] = "/api/operation_mode/disable_diapp_control";
};

struct OperationModeState  //定义 操作模式状态 的消息。
{
  using Message = diapp_adapi_msgs::msg::OperationModeState;
  static constexpr char name[] = "/api/operation_mode/state";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL;
};

}  // namespace diapp_ad_api::operation_mode

#endif  // DIAPP_AD_API_SPECS__OPERATION_MODE_HPP_
