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

#ifndef SERVICE_LOG_CHECKER_HPP_
#define SERVICE_LOG_CHECKER_HPP_

#include <diagnostic_updater/diagnostic_updater.hpp>
#include <rclcpp/rclcpp.hpp>

#include <diapp_system_msgs/msg/service_log.hpp>

#include <string>
#include <unordered_map>

class ServiceLogChecker : public rclcpp::Node
{
public:
  ServiceLogChecker();  //构造函数，用于初始化节点、订阅器和诊断更新器。

private:
  using ServiceLog = diapp_system_msgs::msg::ServiceLog;
  rclcpp::Subscription<ServiceLog>::SharedPtr sub_;  //用于订阅 ServiceLog 消息的订阅器
  diagnostic_updater::Updater diagnostics_;  //用于管理和发布诊断信息的诊断更新器。
  void on_service_log(const ServiceLog::ConstSharedPtr msg);  //服务日志消息的回调函数，根据日志内容调用 set_success 或 set_error 更新状态。
  void set_success(const ServiceLog & msg);  //如果服务日志表示成功，则清除该服务的错误信息。
  void set_error(const ServiceLog & msg, const std::string & log);  //如果服务日志表示失败，则记录错误信息到 errors_ 中。
  void update_diagnostics(diagnostic_updater::DiagnosticStatusWrapper & stat);  //更新诊断状态，将 errors_ 中的错误信息添加到诊断报告中。
  std::unordered_map<std::string, std::string> errors_;  //用于存储服务日志中的错误信息，键为服务名称，值为错误日志。
};

#endif  // SERVICE_LOG_CHECKER_HPP_
