import os
from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import IncludeLaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration, Command
from launch_ros.actions import Node
from launch.conditions import IfCondition
from launch_ros.substitutions import FindPackageShare
from launch.launch_description_sources import PythonLaunchDescriptionSource

def generate_launch_description():
    launch_lidar_localizer = True
    launch_gnss_localizer = True
    launch_fusion_localizer = True
    ### sensor message topic 
    sub_imu_topic = LaunchConfiguration('sub_imu_topic', default='/sensing/imu/openzen_node/imu_raw')
    sub_gnss_topic = LaunchConfiguration('sub_gnss_topic', default='/sensing/gnss/diapp_gnss_ms6111_node/nav_sat_fix')
    sub_lidar_topic = LaunchConfiguration('sub_lidar_topic', default='/sensing/lidar/top/pointcloud_raw_ex')
    sub_vehicle_velocity_topic = LaunchConfiguration('sub_vehicle_velocity_topic', default='/vehicle/status/velocity_status')

    ### sensor coordinate system
    gnss_coor_sys = LaunchConfiguration('gnss_coor_sys', default='gnss_link')
    imu_coor_sys = LaunchConfiguration('imu_coor_sys', default='imu_link')
    lidar_coor_sys = LaunchConfiguration('lidar_coor_sys', default='ls128_top_base_link')
    base_coor_sys = LaunchConfiguration('base_coor_sys', default='base_link')
    world_coor_sys = LaunchConfiguration('world_coor_sys', default='map')

    ### sensor time compensation
    imu_compensation_time = LaunchConfiguration('imu_compensation_time', default='-0.000414348')
    gnss_compensation_time = LaunchConfiguration('gnss_compensation_time', default='-0.144896')
    lidar_compensation_time = LaunchConfiguration('lidar_compensation_time', default='0.0308697')
    vehicle_velocity_compensation_time = LaunchConfiguration('vehicle_velocity_compensation_time', default='-0.15')

    ld = LaunchDescription()

    if(launch_gnss_localizer):
      gnss_localizer = IncludeLaunchDescription(PythonLaunchDescriptionSource([os.path.join(get_package_share_directory('gnss_localizer'), 'launch'),'/gnss_localizer.launch.py']),
                                                                              launch_arguments={'sub_gnss_topic': sub_gnss_topic,
                                                                                                'gnss_compensation_time': gnss_compensation_time}.items())
      ld.add_action(gnss_localizer)

    if(launch_lidar_localizer):
      lidar_localizer = IncludeLaunchDescription(PythonLaunchDescriptionSource([os.path.join(get_package_share_directory('lidar_localizer'), 'launch'),'/lidar_localizer.launch.py']),
                                                                                launch_arguments={'sub_gnss_topic': sub_gnss_topic,
                                                                                                  'sub_imu_topic': sub_imu_topic,
                                                                                                  'sub_lidar_topic': sub_lidar_topic,
                                                                                                  'gnss_coor_sys': gnss_coor_sys,
                                                                                                  'imu_coor_sys': imu_coor_sys,
                                                                                                  'lidar_coor_sys': lidar_coor_sys,
                                                                                                  'world_coor_sys': world_coor_sys,
                                                                                                  'imu_compensation_time': imu_compensation_time,
                                                                                                  'lidar_compensation_time': lidar_compensation_time}.items())
      ld.add_action(lidar_localizer)
      
    if(launch_fusion_localizer):
      fusion_localizer = IncludeLaunchDescription(PythonLaunchDescriptionSource([os.path.join(get_package_share_directory('fusion_localizer_launcher'), 'launch'),'/fusion_localizer.launch.py']),
                                                                                launch_arguments={'sub_gnss_topic': sub_gnss_topic,
                                                                                                  'sub_imu_topic': sub_imu_topic,
                                                                                                  'base_coor_sys': base_coor_sys,
                                                                                                  'gnss_coor_sys': gnss_coor_sys,
                                                                                                  'imu_coor_sys': imu_coor_sys,
                                                                                                  'lidar_coor_sys': lidar_coor_sys,
                                                                                                  'world_coor_sys': world_coor_sys,
                                                                                                  'sub_vehicle_velocity_topic': sub_vehicle_velocity_topic,
                                                                                                  'imu_compensation_time': imu_compensation_time,
                                                                                                  'vehicle_velocity_compensation_time': vehicle_velocity_compensation_time}.items())
      ld.add_action(fusion_localizer)
      
    return ld
