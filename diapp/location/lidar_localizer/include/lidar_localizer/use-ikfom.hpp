#ifndef USE_IKFOM_H
#define USE_IKFOM_H

#include "IKFoM_toolkit/esekfom/esekfom.hpp"

typedef MTK::vect<3, double> vect3;
typedef MTK::SO3<double> SO3;
typedef MTK::S2<double, 98090, 10000, 1> S2; 
typedef MTK::vect<1, double> vect1;
typedef MTK::vect<2, double> vect2;

MTK_BUILD_MANIFOLD(state_ikfom,
((vect3, pos))//3*1
((SO3, rot))//3*1
((SO3, offset_R_L_I))//3*1
((vect3, offset_T_L_I))//3*1
((vect3, vel))//3*1
((vect3, bg))//3*1
((vect3, ba))//3*1
((S2, grav))//3*1
);

MTK_BUILD_MANIFOLD(input_ikfom,
((vect3, acc))
((vect3, gyro))
);

MTK_BUILD_MANIFOLD(process_noise_ikfom,
((vect3, ng))
((vect3, na))
((vect3, nbg))
((vect3, nba))
);

MTK::get_cov<process_noise_ikfom>::type process_noise_cov();

//double L_offset_to_I[3] = {0.04165, 0.02326, -0.0284}; // Avia 
//vect3 Lidar_offset_to_IMU(L_offset_to_I, 3);
// fast_lio2论文公式(2), 起始这里的f就是将imu的积分方程组成矩阵形式然后再去计算
Eigen::Matrix<double, 24, 1> get_f(state_ikfom &s, const input_ikfom &in);

Eigen::Matrix<double, 24, 23> df_dx(state_ikfom &s, const input_ikfom &in);

Eigen::Matrix<double, 24, 12> df_dw(state_ikfom &s, const input_ikfom &in);
//旋转向量转欧拉角参考https://www.cnblogs.com/21207-ihome/p/6894128.html
vect3 SO3ToEuler(const SO3 &orient);

SO3 EulerToSO3(const vect3 euler_ang);

#endif
