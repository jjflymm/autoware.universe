#ifndef LOCATION_POINT_TYPE
#define LOCATION_POINT_TYPE
// #define PCL_NO_PRECOMPILE
#include <pcl/point_types.h>
#include <pcl/point_cloud.h>

namespace PointType
{
    struct PointXYZIT
    {
        PCL_ADD_POINT4D;
        PCL_ADD_INTENSITY
        double time;
        EIGEN_MAKE_ALIGNED_OPERATOR_NEW
    } EIGEN_ALIGN16;

    struct PointXYZRPY
    {
        PCL_ADD_POINT4D;
        PCL_ADD_INTENSITY
        float roll;
        float pitch;
        float yaw;
        EIGEN_MAKE_ALIGNED_OPERATOR_NEW
    } EIGEN_ALIGN16;

    struct PointXYZRPYI
    {
        PCL_ADD_POINT4D;
        float roll;
        float pitch;
        float yaw;
        int idx;
        EIGEN_MAKE_ALIGNED_OPERATOR_NEW
    } EIGEN_ALIGN16;

    struct PointLS
    {
        PCL_ADD_POINT4D;
        PCL_ADD_INTENSITY
        uint16_t ring;
        float azimuth;
        float distance;
        uint8_t return_type;
        double time_stamp;
        EIGEN_MAKE_ALIGNED_OPERATOR_NEW
    } EIGEN_ALIGN16;
}
POINT_CLOUD_REGISTER_POINT_STRUCT(PointType::PointXYZIT,
                                  (float, x, x)(float, y, y)(float, z, z)(float, intensity, intensity)(double, time, time))

POINT_CLOUD_REGISTER_POINT_STRUCT(PointType::PointXYZRPY,
                                  (float, x, x)(float, y, y)(float, z, z)(float, roll, roll)(float, pitch, pitch)(float, yaw, yaw))

POINT_CLOUD_REGISTER_POINT_STRUCT(PointType::PointXYZRPYI,
                                  (float, x, x)(float, y, y)(float, z, z)(float, roll, roll)(float, pitch, pitch)(float, yaw, yaw)(int, idx, idx))

POINT_CLOUD_REGISTER_POINT_STRUCT(PointType::PointLS,
                                  (float, x, x)(float, y, y)(float, z, z)(float, intensity, intensity)(uint16_t, ring, ring)(float, azimuth, azimuth)(uint8_t, return_type, return_type)(double, time_stamp, time_stamp))

using Point_XYZ = pcl::PointXYZ;
using Point_XYZI = pcl::PointXYZI;
using Point_XYZIT = PointType::PointXYZIT;
using Point_XYZRPY = PointType::PointXYZRPY;
using Point_XYZRPYI = PointType::PointXYZRPYI;
using PointCloud_XYZ = pcl::PointCloud<pcl::PointXYZ>;
using PointCloud_XYZI = pcl::PointCloud<pcl::PointXYZI>;
using PointCloud_XYZIT = pcl::PointCloud<PointType::PointXYZIT>;
using PointCloud_XYZRPYI = pcl::PointCloud<PointType::PointXYZRPYI>;
using PointSource = pcl::PointXYZ;
using PointTarget = pcl::PointXYZ;

using LidarPoint = PointType::PointLS;

#endif
