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

#ifndef DIAPP_AD_API_SPECS__INTERFACE_HPP_
#define DIAPP_AD_API_SPECS__INTERFACE_HPP_

#include <diapp_adapi_msgs/srv/interface_version.hpp>

namespace diapp_ad_api::interface
{

struct Version
{
  using Service = diapp_adapi_msgs::srv::InterfaceVersion;
  static constexpr char name[] = "/api/interface/version";
};

}  // namespace diapp_ad_api::interface

#endif  // DIAPP_AD_API_SPECS__INTERFACE_HPP_
