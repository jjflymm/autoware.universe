from launch import LaunchDescription
from launch_ros.actions import Node
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration

def generate_launch_description():
    return LaunchDescription([
        DeclareLaunchArgument('gnss_compensation_time',default_value='-0.144896',description='gnss time compensation,unit is seconds.'),
        DeclareLaunchArgument('world_coordinate_system',default_value='MGRS',description='MGRS,UTM'),
        DeclareLaunchArgument('sub_gnss_topic',default_value='/sensing/gnss/diapp_gnss_ms6111_node/nav_sat_fix',description='subscription gnss topic'),
        DeclareLaunchArgument('sub_course_topic',default_value='/sensing/gnss/diapp_orientation',description='subscription gnss orientation topic'),
        DeclareLaunchArgument('pub_gnss_pose_topic',default_value='/location/gnss/pose',description='publish gnss pose topic'),
        DeclareLaunchArgument('gnss_coor_sys',default_value='gnss_link',description='gnss coordinate system'),
        DeclareLaunchArgument('world_coor_sys',default_value='map',description='world coordinate system'),
        DeclareLaunchArgument('b_use_orientation',default_value='False',description='is use gnss orientation'),
        DeclareLaunchArgument('b_translation',default_value='False',description='is translate gnss'),
        DeclareLaunchArgument('refer_latitude',default_value='22.67916456206',description='the target latitude of gnss translation'),
        DeclareLaunchArgument('refer_longitude',default_value='114.3549381188',description='the target longitude of gnss translation'),
        DeclareLaunchArgument('refer_altitude',default_value='51.2127',description='the target altitude of gnss translation'),
        Node(
            package='gnss_localizer',
            executable='gnss_localizer',
            name='gnss_localizer',
            output='screen',
            parameters=[{'gnss_compensation_time': LaunchConfiguration('gnss_compensation_time')},
                        {'world_coordinate_system': LaunchConfiguration('world_coordinate_system')}, #MGRS  UTM
                        {'sub_gnss_topic': LaunchConfiguration('sub_gnss_topic')},
                        {'sub_course_topic': LaunchConfiguration('sub_course_topic')},
                        {'pub_gnss_pose_topic': LaunchConfiguration('pub_gnss_pose_topic')},
                        {'gnss_coor_sys': LaunchConfiguration('gnss_coor_sys')},
                        {'world_coor_sys': LaunchConfiguration('world_coor_sys')},
                        {'b_use_orientation': LaunchConfiguration('b_use_orientation')},          
                        {'b_translation': LaunchConfiguration('b_translation')},
                        {'refer_latitude': LaunchConfiguration('refer_latitude')},          #refer latitude
                        {'refer_longitude': LaunchConfiguration('refer_longitude')},        #refer longitude
                        {'refer_altitude': LaunchConfiguration('refer_altitude')}           #refer altitude
                        ]
        ),
    ])
