#ifndef LOCATION_IMU_PROCESSING
#define LOCATION_IMU_PROCESSING
#include <cmath>
#include <math.h>
#include <deque>
#include <mutex>
#include <thread>
#include <fstream>
#include <csignal>
#include <rclcpp/rclcpp.hpp>
#include <sophus/types.hpp>
#include "lidar_localizer/so3_math.h"
#include <Eigen/Eigen>
#include <Eigen/Core>
#include <pcl/common/io.h>
#include <pcl/point_cloud.h>
#include <pcl/point_types.h>
#include <condition_variable>
#include <nav_msgs/msg/odometry.hpp>
#include <pcl/common/transforms.h>
#include <pcl/kdtree/kdtree_flann.h>
#include <tf2_ros/transform_broadcaster.h>
#include <tf2_eigen/tf2_eigen.h>
#include <pcl_conversions/pcl_conversions.h>
#include <sensor_msgs/msg/imu.hpp>
#include <sensor_msgs/msg/point_cloud2.hpp>
#include <geometry_msgs/msg/vector3.hpp>
#include "lidar_localizer/use-ikfom.hpp"
#include "lidar_localizer/point_type.hpp"

/// *************Preconfiguration
const unsigned int MAX_INI_COUNT(10);
#define PI_M (3.14159265358)
#define G_m_s2 (9.81)   // Gravaty const in GuangDong/China
#define DIM_STATE (18)  // Dimension of states (Let Dim(SO(3)) = 3)
#define DIM_PROC_N (12) // Dimension of process noise (Let Dim(SO(3)) = 3)
#define CUBE_LEN (6.0)
#define LIDAR_SP_LEN (2)
#define INIT_COV (1)
#define NUM_MATCH_POINTS (5)
#define MAX_MEAS_DIM (10000)

#define VEC_FROM_ARRAY(v) v[0], v[1], v[2]
#define MAT_FROM_ARRAY(v) v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]
#define CONSTRAIN(v, min, max) ((v > min) ? ((v < max) ? v : max) : min)
#define ARRAY_FROM_EIGEN(mat) mat.data(), mat.data() + mat.rows() * mat.cols()
#define STD_VEC_FROM_EIGEN(mat) vector<decltype(mat)::Scalar>(mat.data(), mat.data() + mat.rows() * mat.cols())
// #define DEBUG_FILE_DIR(name) (std::string(std::string(ROOT_DIR) + "Log/" + name))

typedef std::vector<pcl::PointXYZI, Eigen::aligned_allocator<pcl::PointXYZI>> PointVector;
typedef Sophus::Vector3d V3D;
typedef Sophus::Matrix3d M3D;
typedef Sophus::Vector3f V3F;
typedef Sophus::Matrix3f M3F;

#define MD(a, b) Eigen::Matrix<double, (a), (b)>
#define VD(a) Eigen::Matrix<double, (a), 1>
#define MF(a, b) Eigen::Matrix<float, (a), (b)>
#define VF(a) Eigen::Matrix<float, (a), 1>


// M3D Eye3d(M3D::Identity());
// M3F Eye3f(M3F::Identity());
// V3D Zero3d(0, 0, 0);
// V3F Zero3f(0, 0, 0);

struct Pose6D
{
	//the preintegrated Lidar states at the time of IMU measurements in a frame
	double time;        // the  time of IMU measurement 
	double acc[3];       // the preintegrated total acceleration (global frame) at the Lidar origin
	double gyr[3];       // the unbiased angular velocity (body frame) at the Lidar origin
	double vel[3];       // the preintegrated velocity (global frame) at the Lidar origin
	double pos[3];       // the preintegrated position (global frame) at the Lidar origin
	double rot[9];      // the preintegrated rotation (global frame) at the Lidar origin
};

struct MeasureGroup // Lidar data and imu dates for the curent process
{
    MeasureGroup()
    {
        lidar_beg_time = 0.0;
        this->lidar.reset(new PointCloud_XYZIT());
    };
    double lidar_beg_time;
    double lidar_end_time;
    PointCloud_XYZIT::Ptr lidar;
    std::deque<sensor_msgs::msg::Imu> imu;
};

struct StatesGroup
{
    StatesGroup()
    {
        this->rot_end = M3D::Identity();
        this->pos_end = V3D(0, 0, 0);
        this->vel_end = V3D(0, 0, 0);
        this->bias_g = V3D(0, 0, 0);
        this->bias_a = V3D(0, 0, 0);
        this->gravity = V3D(0, 0, 0);
        this->cov = MD(DIM_STATE, DIM_STATE)::Identity() * INIT_COV;
        this->cov.block<9, 9>(9, 9) = MD(9, 9)::Identity() * 0.00001;
    };

    StatesGroup(const StatesGroup &b)
    {
        this->rot_end = b.rot_end;
        this->pos_end = b.pos_end;
        this->vel_end = b.vel_end;
        this->bias_g = b.bias_g;
        this->bias_a = b.bias_a;
        this->gravity = b.gravity;
        this->cov = b.cov;
    };

    StatesGroup &operator=(const StatesGroup &b)
    {
        this->rot_end = b.rot_end;
        this->pos_end = b.pos_end;
        this->vel_end = b.vel_end;
        this->bias_g = b.bias_g;
        this->bias_a = b.bias_a;
        this->gravity = b.gravity;
        this->cov = b.cov;
        return *this;
    };

    StatesGroup operator+(const Eigen::Matrix<double, DIM_STATE, 1> &state_add)
    {
        StatesGroup a;
        a.rot_end = this->rot_end * Exp(state_add(0, 0), state_add(1, 0), state_add(2, 0));
        a.pos_end = this->pos_end + state_add.block<3, 1>(3, 0);
        a.vel_end = this->vel_end + state_add.block<3, 1>(6, 0);
        a.bias_g = this->bias_g + state_add.block<3, 1>(9, 0);
        a.bias_a = this->bias_a + state_add.block<3, 1>(12, 0);
        a.gravity = this->gravity + state_add.block<3, 1>(15, 0);
        a.cov = this->cov;
        return a;
    };

    StatesGroup &operator+=(const Eigen::Matrix<double, DIM_STATE, 1> &state_add)
    {
        this->rot_end = this->rot_end * Exp(state_add(0, 0), state_add(1, 0), state_add(2, 0));
        this->pos_end += state_add.block<3, 1>(3, 0);
        this->vel_end += state_add.block<3, 1>(6, 0);
        this->bias_g += state_add.block<3, 1>(9, 0);
        this->bias_a += state_add.block<3, 1>(12, 0);
        this->gravity += state_add.block<3, 1>(15, 0);
        return *this;
    };

    Eigen::Matrix<double, DIM_STATE, 1> operator-(const StatesGroup &b)
    {
        Eigen::Matrix<double, DIM_STATE, 1> a;
        M3D rotd(b.rot_end.transpose() * this->rot_end);
        a.block<3, 1>(0, 0) = Log(rotd);
        a.block<3, 1>(3, 0) = this->pos_end - b.pos_end;
        a.block<3, 1>(6, 0) = this->vel_end - b.vel_end;
        a.block<3, 1>(9, 0) = this->bias_g - b.bias_g;
        a.block<3, 1>(12, 0) = this->bias_a - b.bias_a;
        a.block<3, 1>(15, 0) = this->gravity - b.gravity;
        return a;
    };

    void resetpose()
    {
        this->rot_end = M3D::Identity();
        this->pos_end = V3D(0, 0, 0);
        this->vel_end = V3D(0, 0, 0);
    }

    M3D rot_end;                              // the estimated attitude (rotation matrix) at the end lidar point
    V3D pos_end;                              // the estimated position at the end lidar point (world frame)
    V3D vel_end;                              // the estimated velocity at the end lidar point (world frame)
    V3D bias_g;                               // gyroscope bias
    V3D bias_a;                               // accelerator bias
    V3D gravity;                              // the estimated gravity acceleration
    Eigen::Matrix<double, DIM_STATE, DIM_STATE> cov; // states covariance
};

/// *************IMU Process and undistortion
class ImuProcess
{
public:
	EIGEN_MAKE_ALIGNED_OPERATOR_NEW

	ImuProcess();
	~ImuProcess();

	void Reset();
	// void Reset(double start_timestamp, const sensor_msgs::ImuConstPtr &lastimu);
	void set_extrinsic(const V3D &transl, const M3D &rot); // 这是外参，平移矩阵3*1,旋转矩阵3*3
	void set_extrinsic(const V3D &transl);				   // 设置平移矩阵3*1
	void set_extrinsic(const MD(4, 4) & T);				   // 设置4*4的变换矩阵
	void set_gyr_cov(const V3D &scaler);				   // 设置3*1的角速度协方差
	void set_acc_cov(const V3D &scaler);				   // 设置3*1的加速度协方差
	void set_gyr_bias_cov(const V3D &b_g);				   // 设置3*1的角速度偏置协方差
	void set_acc_bias_cov(const V3D &b_a);				   // 设置3*1的加速度偏置协方差
	Eigen::Matrix<double, 12, 12> Q;					   // 噪声协方差
	void Process(const MeasureGroup &meas, esekfom::esekf<state_ikfom, 12, input_ikfom> &kf_state, PointCloud_XYZI::Ptr pcl_un_);

	std::ofstream fout_imu;		 // imu输出文件
	V3D cov_acc;			 // 加速度协方差
	V3D cov_gyr;			 // 角速度协方差
	V3D cov_acc_scale;		 // 加速度比例协方差
	V3D cov_gyr_scale;		 // 角速度比例协方差
	V3D cov_bias_gyr;		 // 角速度偏置协方差
	V3D cov_bias_acc;		 // 加速度偏置协方差
	double first_lidar_time; // 第一帧激光雷达时间

private:
	void IMU_init(const MeasureGroup &meas, esekfom::esekf<state_ikfom, 12, input_ikfom> &kf_state, int &N);						 // imu初始化
	void UndistortPcl(const MeasureGroup &meas, esekfom::esekf<state_ikfom, 12, input_ikfom> &kf_state, PointCloud_XYZI &pcl_in_out); // 点云去畸变

	PointCloud_XYZIT::Ptr cur_pcl_un_;	 // 当前未去畸变点云
	sensor_msgs::msg::Imu last_imu_;	 // 上一帧imu数据
	std::deque<sensor_msgs::msg::Imu> v_imu_; // imu队列
	std::vector<Pose6D> IMUpose;				 // imu位姿
	std::vector<M3D> v_rot_pcl_;				 // 3*3的旋转矩阵
	M3D Lidar_R_wrt_IMU;				 // lidar到imu的旋转外参
	V3D Lidar_T_wrt_IMU;				 // lidar到imu的平移外参
	V3D mean_acc;						 // 平均加速度
	V3D mean_gyr;						 // 平均角速度
	V3D angvel_last;					 // 上一帧角速度
	V3D acc_s_last;						 // 上一帧加速度
	double start_timestamp_;			 // 开始时间戳
	double last_lidar_end_time_;		 // 上一帧结束时间戳
	int init_iter_num = 1;				 // 初始化迭代次数，默认是1
	bool b_first_frame_ = true;			 // 是否是开始帧，或者是第一帧
	bool imu_need_init_ = true;			 // 是否进行imu初始化

	template <typename T>
	auto set_pose6d(const double t, const Eigen::Matrix<T, 3, 1> &a, const Eigen::Matrix<T, 3, 1> &g,
                const Eigen::Matrix<T, 3, 1> &v, const Eigen::Matrix<T, 3, 1> &p, const Eigen::Matrix<T, 3, 3> &R);
};

template <typename T>
auto ImuProcess::set_pose6d(const double t, const Eigen::Matrix<T, 3, 1> &a, const Eigen::Matrix<T, 3, 1> &g,
                const Eigen::Matrix<T, 3, 1> &v, const Eigen::Matrix<T, 3, 1> &p, const Eigen::Matrix<T, 3, 3> &R)
{
    Pose6D rot_kp;
    rot_kp.time = t;
    for (int i = 0; i < 3; i++)
    {
        rot_kp.acc[i] = a(i);
        rot_kp.gyr[i] = g(i);
        rot_kp.vel[i] = v(i);
        rot_kp.pos[i] = p(i);
        for (int j = 0; j < 3; j++)
            rot_kp.rot[i * 3 + j] = R(i, j);
    }
    return std::move(rot_kp);
}

#endif

