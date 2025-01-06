import os
from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration, Command
from launch_ros.actions import Node

def generate_launch_description():
    root_dir = get_package_share_directory('lidar_localizer')

    return LaunchDescription([
        DeclareLaunchArgument('imu_compensation_time',default_value='-0.000414348',description='imu time compensation,unit is seconds.'),
        DeclareLaunchArgument('lidar_compensation_time',default_value='0.0308697',description='lidar time compensation,unit is seconds.'),
        DeclareLaunchArgument('params_file',default_value=os.path.join(root_dir, 'config', 'lidar_location.params.yaml'),description='FPath to the ROS2 parameters file to use.'),
        DeclareLaunchArgument('map_path',default_value='/home/adam/DiAPP/map',description='the point cloud map path.'),
        DeclareLaunchArgument('sub_gnss_pose_topic',default_value='/location/gnss/pose',description='subscription gnss pose topic'),
        DeclareLaunchArgument('sub_lidar_topic',default_value='/sensing/lidar/top/pointcloud_raw_ex',description='subscription lidar topic'),
        DeclareLaunchArgument('sub_imu_topic',default_value='/sensing/imu/openzen_node/imu_raw',description='subscription imu topic'),
        DeclareLaunchArgument('pub_lidar_pose_topic',default_value='/location/lidar/pose',description='publish lidar pose topic'),
        DeclareLaunchArgument('gnss_coor_sys',default_value='gnss_link',description='gnss coordinate system'),
        DeclareLaunchArgument('imu_coor_sys',default_value='imu_link',description='imu coordinate system'),
        DeclareLaunchArgument('lidar_coor_sys',default_value='top_lidar_link',description='lidar coordinate system'),
        DeclareLaunchArgument('base_coor_sys',default_value='base_link',description='base coordinate system'),
        DeclareLaunchArgument('world_coor_sys',default_value='map',description='world coordinate system'),
        Node(
            package='lidar_localizer',
            executable='lidar_localizer',
            name='lidar_localizer',
            output='screen',
            parameters=[{LaunchConfiguration('params_file')},
                        {'imu_compensation_time': LaunchConfiguration('imu_compensation_time')},
                        {'lidar_compensation_time': LaunchConfiguration('lidar_compensation_time')},
                        {'map_path': LaunchConfiguration('map_path')}, #地图路劲
                        {'sub_gnss_pose_topic': LaunchConfiguration('sub_gnss_pose_topic')},
                        {"sub_lidar_topic": LaunchConfiguration('sub_lidar_topic')},
                        {"sub_imu_topic": LaunchConfiguration('sub_imu_topic')},
                        {"pub_lidar_pose_topic": LaunchConfiguration('pub_lidar_pose_topic')},
                        {"imu_coor_sys": LaunchConfiguration('imu_coor_sys')},
                        {"lidar_coor_sys": LaunchConfiguration('lidar_coor_sys')},
                        {"base_coor_sys": LaunchConfiguration('base_coor_sys')},
                        {"world_coor_sys": LaunchConfiguration('world_coor_sys')}
                        ]
        )
    ])

                        
