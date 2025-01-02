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

#ifndef COMPONENT_INTERFACE_SPECS__SYSTEM_HPP_
#define COMPONENT_INTERFACE_SPECS__SYSTEM_HPP_

#include <rclcpp/qos.hpp>

#include <diapp_adapi_msgs/msg/mrm_state.hpp>
#include <diapp_adapi_msgs/msg/operation_mode_state.hpp>
#include <diapp_system_msgs/srv/change_diapp_control.hpp>
#include <diapp_system_msgs/srv/change_operation_mode.hpp>

namespace system_interface
{

struct MrmState  //用于获取最小风险策略（MRM，Minimum Risk Maneuver）状态的主题。通过订阅该主题，可以实时监控系统是否处于应急状态。
{
  using Message = diapp_adapi_msgs::msg::MrmState;
  static constexpr char name[] = "/system/fail_safe/mrm_state";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;  //确保消息可靠传输
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_VOLATILE;  //表示消息不会持久化，订阅者只能接收到发布时的最新消息
};

struct ChangeDiappControl  //用于更改Diapp控制模式的服务。通过调用该服务，可以切换系统的控制权限（例如，从手动控制切换到自动控制）。
{
  using Service = diapp_system_msgs::srv::ChangeDiappControl;
  static constexpr char name[] = "/system/operation_mode/change_diapp_control";
};

struct ChangeOperationMode  //用于更改操作模式的服务。通过调用该服务，可以切换系统的操作模式（例如，从正常模式切换到紧急模式）。
{
  using Service = diapp_system_msgs::srv::ChangeOperationMode;
  static constexpr char name[] = "/system/operation_mode/change_operation_mode";
};

struct OperationModeState  //用于获取操作模式状态的主题。通过订阅该主题，可以实时监控系统的当前操作模式（例如，手动模式、自动模式、紧急模式等）。
{
  using Message = diapp_adapi_msgs::msg::OperationModeState;
  static constexpr char name[] = "/system/operation_mode/state";
  static constexpr size_t depth = 1;
  static constexpr auto reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  static constexpr auto durability = RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL; //确保消息在订阅者加入后仍然可用
};

}  // namespace system_interface

#endif  // COMPONENT_INTERFACE_SPECS__SYSTEM_HPP_
