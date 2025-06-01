-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jun 01, 2025 at 07:38 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET FOREIGN_KEY_CHECKS=0;
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `realestate_db`
--
CREATE DATABASE IF NOT EXISTS `realestate_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `realestate_db`;

-- --------------------------------------------------------

--
-- Table structure for table `admin_service_visibility`
--

DROP TABLE IF EXISTS `admin_service_visibility`;
CREATE TABLE IF NOT EXISTS `admin_service_visibility` (
  `admin_id` int(11) NOT NULL,
  `service_id` int(11) NOT NULL,
  `is_enabled` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`admin_id`,`service_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `admin_service_visibility`
--

INSERT DELAYED IGNORE INTO `admin_service_visibility` (`admin_id`, `service_id`, `is_enabled`) VALUES
(2, 1, 1),
(2, 2, 1),
(2, 3, 1),
(2, 4, 1),
(2, 5, 1),
(2, 6, 1),
(2, 7, 1),
(2, 8, 1),
(2, 9, 1),
(4, 1, 1),
(4, 2, 1),
(4, 3, 1),
(4, 4, 1),
(4, 5, 1),
(4, 6, 1),
(4, 7, 1),
(4, 8, 1),
(4, 9, 1),
(5, 1, 1),
(5, 2, 1),
(5, 3, 1),
(5, 4, 1),
(5, 5, 1),
(5, 6, 1),
(5, 7, 1),
(5, 8, 1),
(5, 9, 1),
(8, 1, 1),
(8, 2, 1),
(8, 3, 1),
(8, 4, 1),
(8, 5, 1),
(8, 6, 1),
(8, 7, 1),
(8, 8, 1),
(8, 9, 1),
(9, 1, 1),
(9, 2, 1),
(9, 3, 1),
(9, 4, 1),
(9, 5, 1),
(9, 6, 1),
(9, 7, 1),
(9, 8, 1),
(9, 9, 1),
(10, 1, 1),
(10, 2, 1),
(10, 3, 1),
(10, 4, 1),
(10, 5, 1),
(10, 6, 1),
(10, 7, 1),
(10, 8, 1),
(10, 9, 1);

-- --------------------------------------------------------

--
-- Table structure for table `admin_subscriptions`
--

DROP TABLE IF EXISTS `admin_subscriptions`;
CREATE TABLE IF NOT EXISTS `admin_subscriptions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `admin_id` int(11) NOT NULL,
  `start_date` date NOT NULL,
  `end_date` date NOT NULL,
  `status` enum('active','expired','cancelled') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `admin_id` (`admin_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `admin_subscriptions`
--

INSERT DELAYED IGNORE INTO `admin_subscriptions` (`id`, `admin_id`, `start_date`, `end_date`, `status`, `created_at`) VALUES
(1, 2, '2025-05-28', '2025-05-27', 'active', '2025-05-28 14:47:10'),
(2, 2, '2025-05-28', '2025-05-27', 'active', '2025-05-28 15:07:16'),
(3, 2, '2025-05-28', '2025-05-27', 'active', '2025-05-28 15:16:21'),
(4, 2, '2025-05-28', '2025-06-27', 'active', '2025-05-28 15:22:40'),
(5, 4, '2025-05-29', '2025-06-06', 'active', '2025-05-29 20:44:43');

-- --------------------------------------------------------

--
-- Table structure for table `admin_subscription_extensions`
--

DROP TABLE IF EXISTS `admin_subscription_extensions`;
CREATE TABLE IF NOT EXISTS `admin_subscription_extensions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `subscription_id` int(11) NOT NULL,
  `extended_by` int(11) NOT NULL,
  `extension_start` date NOT NULL,
  `extension_end` date NOT NULL,
  `extension_days` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `subscription_id` (`subscription_id`),
  KEY `extended_by` (`extended_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `admin_tokens`
--

DROP TABLE IF EXISTS `admin_tokens`;
CREATE TABLE IF NOT EXISTS `admin_tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `token` varchar(255) NOT NULL,
  `permissions` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`permissions`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  KEY `created_by` (`created_by`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `admin_tokens`
--

INSERT DELAYED IGNORE INTO `admin_tokens` (`id`, `token`, `permissions`, `created_at`, `created_by`) VALUES
(1, 'e3743c095c04e6ea6a4323a9aa14ac51035fc4376dd6e522bc971b84ffc16db2', '{\"manage_units\":true,\"add_user\":true,\"view_bills\":false}', '2025-05-28 11:26:42', 1),
(2, 'e5feb2a67bdd58d9ff78e2059ded6496e2aa112d087215fe0fc3ed4b6e03b4e2', '{\"manage_units\":true,\"add_user\":true,\"view_bills\":false}', '2025-05-28 11:28:04', 1),
(3, '3b53d4c5a099e66928ae3bf0533b727092fe2ec84f8b664633eff12a053ca63a', '{\"manage_units\":true,\"add_user\":true,\"view_bills\":false}', '2025-05-28 11:28:06', 1),
(4, '5703cc831c1f919c66cbba624bc9b8c86a6074178f1321e289842a16b637e325', '{\"manage_units\":true,\"add_user\":true,\"view_bills\":false}', '2025-05-28 11:28:06', 1),
(5, '84b84882aa733b3056746201ce2de396f539d4a30a3f11c451a00f38d41d5a23', '{\"manage_units\":true,\"add_user\":true,\"view_bills\":false}', '2025-05-28 11:28:07', 1),
(6, '38d16e4b47a605ed57a19bd780a3382c9a1eefaf37ae96cced456990d8c90d6d', '{\"manage_units\":true}', '2025-05-28 14:05:10', 2),
(7, '507a6027d2e84d2a5096ffb28da2dd43d4577e2bb3a2f49109430f2930f2859d', '{\"manage_units\":true}', '2025-05-28 17:02:34', 2),
(10, '544945a5229641fa25f1ae916452249fcd12d11c3f08e8c90b36d54be0c33c51', '{}', '2025-05-31 19:49:59', 1);

-- --------------------------------------------------------

--
-- Table structure for table `chat_rooms`
--

DROP TABLE IF EXISTS `chat_rooms`;
CREATE TABLE IF NOT EXISTS `chat_rooms` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `contract_id` int(11) DEFAULT NULL,
  `tenant_user_id` varchar(255) DEFAULT NULL,
  `admin_user_id` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `contract_id` (`contract_id`),
  KEY `tenant_user_id` (`tenant_user_id`),
  KEY `admin_user_id` (`admin_user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=35 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `chat_rooms`
--

INSERT DELAYED IGNORE INTO `chat_rooms` (`id`, `contract_id`, `tenant_user_id`, `admin_user_id`, `created_at`) VALUES
(19, 90, 'tenantuser', 'adminuser', '2025-05-31 18:45:54'),
(20, 91, 'tenant1', 'admin1', '2025-05-31 18:49:13'),
(34, 109, 'tenant_test', 'admin1', '2025-05-31 20:00:48');

-- --------------------------------------------------------

--
-- Table structure for table `dynamic_services`
--

DROP TABLE IF EXISTS `dynamic_services`;
CREATE TABLE IF NOT EXISTS `dynamic_services` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(100) NOT NULL,
  `icon` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `is_default` tinyint(1) DEFAULT 0,
  `route` varchar(255) DEFAULT NULL,
  `display_order` int(11) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `dynamic_services`
--

INSERT DELAYED IGNORE INTO `dynamic_services` (`id`, `title`, `icon`, `description`, `is_active`, `is_default`, `route`, `display_order`) VALUES
(1, 'خدمة النت', 'wifi', 'تفاصيل واعدادات خدمة الإنترنت للمستأجر', 1, 1, '/internet-service', 1),
(2, 'أمين الشقة', 'shield', 'طلب خدمة مراقبة الشقة في غيابك', 1, 1, '/apartment-security', 2),
(3, 'تنظيف', 'cleaning_services', 'طلب تنظيف الشقة حسب الجدولة أو عند الطلب', 0, 0, '/cleaning-service', 0),
(4, 'صيانة عاجلة', 'build_circle', 'طلب تدخل فوري لحل مشكلة عاجلة', 1, 1, '/urgent-maintenance', 5),
(5, 'بلاغ أعطال', 'report_problem', 'صفحة إرسال بلاغ عن عطل معين', 0, 0, '/report-problem', 0),
(6, 'تحميل عقدك', 'file_download', 'تحميل نسخة العقد PDF الخاصة بك', 1, 1, '/download-contract', 4),
(7, 'خدمة توصيل مياه', 'local_drink', 'طلب مياه للمجمع أو الشقة مباشرة', 1, 1, '/water-delivery', 8),
(8, 'تنبيه موعد الدفعة', 'notifications_active', 'تفعيل التنبيه قرب موعد دفع الإيجار', 1, 1, '/payment-alert', 3),
(9, 'تواصل مع الدعم', 'support_agent', 'اتصل مباشرة بفريق الدعم لأي مشكلة', 1, 1, '/support-contact', 11),
(10, 'خدمة تعقيم الشقة', 'sanitizer', 'طلب تعقيم دوري أو مرة واحدة للشقة', 0, 0, NULL, 0),
(11, 'تفعيل التنبيهات الذكية', 'sms', 'استقبال تنبيهات SMS ورسائل دفع', 0, 0, NULL, 0),
(12, 'دليل المستأجر', 'menu_book', 'معلومات وشروط السكن وحقوقك', 0, 0, NULL, 0),
(13, 'التقييمات والملاحظات', 'star_rate', 'سجل تقييماتك والملاحظات مع نقاطك', 0, 0, NULL, 0),
(14, 'طلب تمديد عقد', 'event_repeat', 'أرسل طلب تمديد فترة الإيجار مباشرة', 0, 0, NULL, 0),
(15, 'اشتراك شهري للخدمات', 'subscriptions', 'باقة خدمات خاصة شهريًا للمستأجرين', 0, 0, NULL, 0),
(16, 'أرسل اقتراح أو شكوى', 'feedback', 'أرسل ملاحظتك مباشرة للإدارة', 0, 0, NULL, 0),
(17, 'خدمة تغيير الأقفال', 'lock_reset', 'طلب تغيير أو صيانة الأقفال', 0, 0, NULL, 0),
(18, 'مساعد الطاقة الكهربائية', 'bolt', 'تعقب وتحسين استهلاك الكهرباء', 0, 0, NULL, 0),
(19, 'جدولة التنظيف الدوري', 'calendar_today', 'اختر مواعيد تنظيف أسبوعية/شهرية', 0, 0, NULL, 0),
(20, 'تحديث بيانات السكن', 'home_work', 'تحديث موقع الشقة أو بيانات الاتصال', 0, 0, NULL, 0),
(21, 'طلب خدمة تنظيف متخصصة', 'cleaning_services', 'طلب تنظيف متخصص لمناطق أو أوقات محددة', 1, 1, 'cleaningServiceRequest', 7),
(22, 'طلب تغيير الأقفال', 'lock_reset', 'طلب تغيير أقفال الشقة لأسباب أمنية أو فنية', 1, 1, 'changeLocksRequest', 9),
(23, 'بلاغ إزعاج', 'volume_off', 'الإبلاغ عن إزعاج من جيران أو أعمال في العقار', 1, 1, 'noiseComplaintRequest', 10),
(24, 'طلب مستلزمات الشقة', 'inventory', 'طلب أدوات أو مستلزمات صغيرة لصيانة الشقة', 1, 1, 'apartmentSuppliesRequest', 6);

-- --------------------------------------------------------

--
-- Table structure for table `maintenance_requests`
--

DROP TABLE IF EXISTS `maintenance_requests`;
CREATE TABLE IF NOT EXISTS `maintenance_requests` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tenant_id` int(11) NOT NULL,
  `owner_id` int(11) NOT NULL,
  `category` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `status` varchar(50) DEFAULT 'معلقة',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `maintenance_requests`
--

INSERT DELAYED IGNORE INTO `maintenance_requests` (`id`, `tenant_id`, `owner_id`, `category`, `description`, `status`, `created_at`) VALUES
(1, 6, 4, 'مشكلة أخرى', 'hskshgacafa shaagtw', 'معلقة', '2025-05-30 18:25:28'),
(2, 6, 4, 'مشكلة أخرى', 'gghlcf', 'معلقة', '2025-05-30 18:25:59'),
(3, 6, 4, 'انسداد المجاري', 'getstat', 'معلقة', '2025-05-30 18:27:51'),
(4, 6, 4, 'تسريب في الحمام', 'ywtscatayafaf', 'معلقة', '2025-05-30 18:56:01'),
(5, 6, 4, 'مشاكل في المواقف', 'الدي مشكلة لا اجد موقفي متوفر دائما', 'معلقة', '2025-05-31 00:05:54'),
(6, 11, 4, 'مشكلة في المياه', 'يوجد لدي مشكله في المياه', 'معلقة', '2025-05-31 20:22:42'),
(7, 11, 4, 'انسداد المجاري', 'fddtwggsg', 'معلقة', '2025-05-31 22:58:27'),
(8, 11, 4, 'عطل في الكهرباء', '', 'معلقة', '2025-05-31 23:21:41'),
(9, 11, 4, 'عطل في الكهرباء', '', 'معلقة', '2025-05-31 23:22:04'),
(10, 11, 4, 'عطل في الكهرباء', '', 'معلقة', '2025-05-31 23:22:07'),
(11, 11, 4, 'عطل في الكهرباء', '', 'معلقة', '2025-05-31 23:22:07'),
(12, 11, 4, 'مشكلة أخرى', 'yeysgsgsyg', 'معلقة', '2025-05-31 23:24:26'),
(13, 11, 4, 'مشكلة في المياه', 'gayagacT', 'معلقة', '2025-05-31 23:25:31'),
(14, 11, 4, 'مشكلة في المياه', 'hellehzggeg', 'معلقة', '2025-05-31 23:27:20'),
(15, 11, 4, 'مشكلة في المياه', 'ywgafafaf', 'معلقة', '2025-05-31 23:29:04'),
(16, 11, 4, 'عطل في الكهرباء', 'gsysysff', 'معلقة', '2025-05-31 23:43:48'),
(17, 11, 4, 'مشكلة أخرى', 'yeysgsgss', 'معلقة', '2025-05-31 23:48:13'),
(18, 11, 4, 'عطل في الكهرباء', 'ysystwff', 'معلقة', '2025-05-31 23:51:19'),
(19, 11, 4, 'عطل في الكهرباء', 'gdgsygscwgzg', 'معلقة', '2025-06-01 00:16:38'),
(20, 11, 4, 'مشاكل في المواقف', 'هلوووو', 'معلقة', '2025-06-01 02:00:40');

-- --------------------------------------------------------

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
CREATE TABLE IF NOT EXISTS `messages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `contract_id` int(11) NOT NULL,
  `sender_id` varchar(255) NOT NULL,
  `receiver_id` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  `is_read` tinyint(1) DEFAULT 0,
  `chat_room_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `contract_id` (`contract_id`),
  KEY `sender_id` (`sender_id`),
  KEY `receiver_id` (`receiver_id`),
  KEY `chat_room_id` (`chat_room_id`)
) ENGINE=InnoDB AUTO_INCREMENT=60 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `messages`
--

INSERT DELAYED IGNORE INTO `messages` (`id`, `contract_id`, `sender_id`, `receiver_id`, `message`, `timestamp`, `is_read`, `chat_room_id`) VALUES
(58, 109, 'tenant_test', 'admin1', 'مرحبا', '2025-05-31 23:23:00', 0, 34),
(59, 109, 'tenant_test', 'admin1', '😝😛😝😋', '2025-05-31 23:23:04', 0, 34);

-- --------------------------------------------------------

--
-- Table structure for table `noise_complaints`
--

DROP TABLE IF EXISTS `noise_complaints`;
CREATE TABLE IF NOT EXISTS `noise_complaints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tenant_id` int(11) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `category` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `status` enum('جديد','قيد المعالجة','تم الحل') DEFAULT 'جديد',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `tenant_id` (`tenant_id`),
  KEY `admin_id` (`admin_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `noise_complaints`
--

INSERT DELAYED IGNORE INTO `noise_complaints` (`id`, `tenant_id`, `admin_id`, `category`, `description`, `status`, `created_at`, `updated_at`) VALUES
(1, 11, 4, 'موسيقى مرتفعة', 'ysystsfsyaga', 'جديد', '2025-06-01 03:19:18', '2025-06-01 03:19:18'),
(2, 11, 4, 'مشاجرات أو مشاكل خارجية', 'chdtsss', 'جديد', '2025-06-01 03:21:34', '2025-06-01 03:21:34'),
(3, 11, 4, 'غير ذلك', 'ufudydds', 'جديد', '2025-06-01 03:21:45', '2025-06-01 03:21:45'),
(4, 11, 4, 'غير ذلك', '', 'جديد', '2025-06-01 03:23:01', '2025-06-01 03:23:01'),
(5, 11, 4, 'غير ذلك', 'gggg', 'جديد', '2025-06-01 03:23:10', '2025-06-01 03:23:10'),
(6, 11, 4, 'مشاجرات أو مشاكل خارجية', '', 'جديد', '2025-06-01 03:23:18', '2025-06-01 03:23:18');

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

DROP TABLE IF EXISTS `notifications`;
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` varchar(255) DEFAULT NULL,
  `title` varchar(255) DEFAULT NULL,
  `body` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `is_read` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=42 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `notifications`
--

INSERT DELAYED IGNORE INTO `notifications` (`id`, `user_id`, `title`, `body`, `created_at`, `is_read`) VALUES
(1, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:05:12', 1),
(2, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:05:15', 1),
(3, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:10:51', 1),
(4, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:10:53', 1),
(5, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:10:54', 1),
(6, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:10:55', 1),
(7, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:10:56', 1),
(8, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:10:56', 1),
(9, 'tenant1', 'تنبيه جديد', 'مرحباً! تم إرسال هذا الإشعار بنجاح ✅', '2025-05-30 17:10:56', 1),
(10, 'tenant1', 'تنبيه جديد', 'هلووووووووووووووووووو يووووسف ✅', '2025-05-30 17:23:59', 1),
(11, 'tenant1', 'تنبيه جديد', 'هلووووووووووووووووووو يووووسف ✅', '2025-05-30 17:24:01', 1),
(12, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:24:26', 1),
(13, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:26:19', 1),
(14, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:36:36', 1),
(15, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:36:37', 1),
(16, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:36:38', 1),
(17, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:40:34', 1),
(18, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:47:05', 1),
(19, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:48:31', 1),
(20, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:48:52', 1),
(21, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:51:56', 1),
(22, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:51:58', 1),
(23, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:51:59', 1),
(24, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:52:00', 1),
(25, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:52:00', 1),
(26, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:52:01', 1),
(27, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:52:01', 1),
(28, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:52:01', 1),
(29, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:52:02', 1),
(30, 'tenant1', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-30 17:52:02', 1),
(31, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-31 22:54:16', 1),
(32, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-31 22:54:17', 1),
(33, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-31 22:54:18', 1),
(34, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-31 22:54:39', 1),
(35, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-05-31 22:54:55', 1),
(36, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-06-01 00:42:06', 1),
(37, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-06-01 00:42:24', 1),
(38, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-06-01 01:54:17', 1),
(39, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-06-01 01:54:30', 1),
(40, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-06-01 01:54:31', 1),
(41, 'tenant_test', 'تنبيه جديد', 'هلوووووووووووشسي شسي شسي شسي شسي شسي شسي شسي شسيشس يشسي سشي شس يشس يوووووووو يووووسف ✅', '2025-06-01 01:54:32', 1);

-- --------------------------------------------------------

--
-- Table structure for table `payments`
--

DROP TABLE IF EXISTS `payments`;
CREATE TABLE IF NOT EXISTS `payments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `contract_id` int(11) NOT NULL,
  `payment_number` int(11) NOT NULL,
  `payment_amount` decimal(10,2) NOT NULL,
  `due_date` date NOT NULL,
  `payment_status` enum('مدفوعة','معلقة','غير مدفوعة') DEFAULT 'غير مدفوعة',
  `paid_date` date DEFAULT NULL,
  `payment_note` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `contract_id` (`contract_id`)
) ENGINE=InnoDB AUTO_INCREMENT=595 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `payments`
--

INSERT DELAYED IGNORE INTO `payments` (`id`, `contract_id`, `payment_number`, `payment_amount`, `due_date`, `payment_status`, `paid_date`, `payment_note`) VALUES
(505, 90, 1, 1500.00, '2025-05-05', 'مدفوعة', NULL, NULL),
(506, 90, 2, 1500.00, '2025-06-05', 'مدفوعة', NULL, NULL),
(507, 90, 3, 1500.00, '2025-07-05', 'مدفوعة', NULL, NULL),
(508, 90, 4, 1500.00, '2025-08-05', 'مدفوعة', NULL, NULL),
(509, 90, 5, 1500.00, '2025-09-05', 'مدفوعة', NULL, NULL),
(510, 90, 6, 1500.00, '2025-10-05', 'مدفوعة', NULL, NULL),
(511, 90, 7, 1500.00, '2025-11-05', 'غير مدفوعة', NULL, NULL),
(512, 90, 8, 1500.00, '2025-12-05', 'غير مدفوعة', NULL, NULL),
(513, 90, 9, 1500.00, '2026-01-05', 'غير مدفوعة', NULL, NULL),
(514, 90, 10, 1500.00, '2026-02-05', 'غير مدفوعة', NULL, NULL),
(515, 90, 11, 1500.00, '2026-03-05', 'غير مدفوعة', NULL, NULL),
(516, 90, 12, 1500.00, '2026-04-05', 'غير مدفوعة', NULL, NULL),
(523, 91, 1, 1500.00, '2025-05-02', 'مدفوعة', NULL, NULL),
(524, 91, 2, 1500.00, '2025-06-02', 'مدفوعة', NULL, NULL),
(525, 91, 3, 1500.00, '2025-07-02', 'مدفوعة', NULL, NULL),
(526, 91, 4, 1500.00, '2025-08-02', 'مدفوعة', NULL, NULL),
(527, 91, 5, 1500.00, '2025-09-02', 'غير مدفوعة', NULL, NULL),
(528, 91, 6, 1500.00, '2025-10-02', 'غير مدفوعة', NULL, NULL),
(529, 91, 7, 1500.00, '2025-11-02', 'غير مدفوعة', NULL, NULL),
(530, 91, 8, 1500.00, '2025-12-02', 'غير مدفوعة', NULL, NULL),
(531, 91, 9, 1500.00, '2026-01-02', 'غير مدفوعة', NULL, NULL),
(532, 91, 10, 1500.00, '2026-02-02', 'غير مدفوعة', NULL, NULL),
(533, 91, 11, 1500.00, '2026-03-02', 'غير مدفوعة', NULL, NULL),
(534, 91, 12, 1500.00, '2026-04-02', 'غير مدفوعة', NULL, NULL),
(583, 109, 1, 1300.00, '2025-05-31', 'غير مدفوعة', NULL, NULL),
(584, 109, 2, 1300.00, '2025-06-30', 'غير مدفوعة', NULL, NULL),
(585, 109, 3, 1300.00, '2025-07-31', 'غير مدفوعة', NULL, NULL),
(586, 109, 4, 1300.00, '2025-08-31', 'غير مدفوعة', NULL, NULL),
(587, 109, 5, 1300.00, '2025-09-30', 'غير مدفوعة', NULL, NULL),
(588, 109, 6, 1300.00, '2025-10-31', 'غير مدفوعة', NULL, NULL),
(589, 109, 7, 1300.00, '2025-11-30', 'غير مدفوعة', NULL, NULL),
(590, 109, 8, 1300.00, '2025-12-31', 'غير مدفوعة', NULL, NULL),
(591, 109, 9, 1300.00, '2026-01-31', 'غير مدفوعة', NULL, NULL),
(592, 109, 10, 1300.00, '2026-02-28', 'غير مدفوعة', NULL, NULL),
(593, 109, 11, 1300.00, '2026-03-31', 'غير مدفوعة', NULL, NULL),
(594, 109, 12, 1300.00, '2026-04-30', 'غير مدفوعة', NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `payment_alert_settings`
--

DROP TABLE IF EXISTS `payment_alert_settings`;
CREATE TABLE IF NOT EXISTS `payment_alert_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `is_enabled` tinyint(1) DEFAULT 1,
  `days_before` int(11) DEFAULT 3,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `payment_alert_settings`
--

INSERT DELAYED IGNORE INTO `payment_alert_settings` (`id`, `user_id`, `is_enabled`, `days_before`, `created_at`, `updated_at`) VALUES
(1, 11, 1, 5, '2025-06-01 03:52:53', '2025-06-01 03:52:53'),
(2, 11, 1, 7, '2025-06-01 03:54:23', '2025-06-01 03:54:23'),
(3, 11, 1, 1, '2025-06-01 03:55:46', '2025-06-01 03:55:46'),
(4, 11, 1, 7, '2025-06-01 03:56:29', '2025-06-01 03:56:29');

-- --------------------------------------------------------

--
-- Table structure for table `rental_contracts`
--

DROP TABLE IF EXISTS `rental_contracts`;
CREATE TABLE IF NOT EXISTS `rental_contracts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tenant_id` int(11) NOT NULL,
  `property_name` varchar(255) DEFAULT NULL,
  `rent_amount` decimal(10,2) DEFAULT NULL,
  `contract_start` date NOT NULL,
  `contract_end` date NOT NULL,
  `status` enum('active','expired','terminated') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `tenant_id` (`tenant_id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `rental_contracts`
--

INSERT DELAYED IGNORE INTO `rental_contracts` (`id`, `tenant_id`, `property_name`, `rent_amount`, `contract_start`, `contract_end`, `status`, `created_at`) VALUES
(4, 6, 'عقار مستأجر', 1250.00, '2024-08-25', '2024-11-24', 'active', '2025-05-31 18:49:13'),
(5, 3, 'عقار مستأجر', 1250.00, '2024-07-28', '2025-07-27', 'active', '2025-05-31 18:45:54'),
(7, 11, 'عقار مستأجر', 1300.00, '2025-05-31', '2026-05-31', 'active', '2025-05-31 20:00:48');

-- --------------------------------------------------------

--
-- Table structure for table `rental_contracts_details`
--

DROP TABLE IF EXISTS `rental_contracts_details`;
CREATE TABLE IF NOT EXISTS `rental_contracts_details` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `contract_number` varchar(255) DEFAULT NULL,
  `contract_type` varchar(255) DEFAULT NULL,
  `contract_date` date DEFAULT NULL,
  `contract_start` date DEFAULT NULL,
  `contract_end` date DEFAULT NULL,
  `contract_location` varchar(255) DEFAULT NULL,
  `owner_name` varchar(255) DEFAULT NULL,
  `owner_nationality` varchar(100) DEFAULT NULL,
  `owner_id_type` varchar(100) DEFAULT NULL,
  `owner_id_number` varchar(100) DEFAULT NULL,
  `owner_email` varchar(255) DEFAULT NULL,
  `owner_phone` varchar(50) DEFAULT NULL,
  `owner_address` varchar(255) DEFAULT NULL,
  `tenant_name` varchar(255) DEFAULT NULL,
  `tenant_nationality` varchar(100) DEFAULT NULL,
  `tenant_id_type` varchar(100) DEFAULT NULL,
  `tenant_id_number` varchar(100) DEFAULT NULL,
  `tenant_email` varchar(255) DEFAULT NULL,
  `tenant_phone` varchar(50) DEFAULT NULL,
  `tenant_address` varchar(255) DEFAULT NULL,
  `property_national_address` varchar(255) DEFAULT NULL,
  `property_building_type` varchar(100) DEFAULT NULL,
  `property_usage` varchar(100) DEFAULT NULL,
  `property_units_count` int(11) DEFAULT NULL,
  `property_floors_count` int(11) DEFAULT NULL,
  `unit_type` varchar(100) DEFAULT NULL,
  `unit_number` varchar(50) DEFAULT NULL,
  `unit_floor_number` int(11) DEFAULT NULL,
  `unit_area` decimal(10,2) DEFAULT NULL,
  `unit_furnishing_status` varchar(100) DEFAULT NULL,
  `unit_ac_units_count` int(11) DEFAULT NULL,
  `unit_ac_type` varchar(100) DEFAULT NULL,
  `annual_rent` decimal(10,2) DEFAULT NULL,
  `periodic_rent_payment` decimal(10,2) DEFAULT NULL,
  `rent_payment_cycle` varchar(50) DEFAULT NULL,
  `rent_payments_count` int(11) DEFAULT NULL,
  `total_contract_value` decimal(12,2) DEFAULT NULL,
  `terms_conditions` text NOT NULL DEFAULT '\nالمادة الأولى: البيانات السابقة على التزامات الأطراف تعد جزءًا لا يتجزأ من هذا العقد ومفسّرة ومكمّلة له.\nالمادة الثانية: محل العقد اتفق المؤجر والمستأجر على تأجير الوحدات الإيجارية وفقًا للشروط المذكورة.\nالمادة الثالثة: مدة الإيجار (364 يومًا) تبدأ من تاريخ العقد وتنتهي في التاريخ المحدد.\nالمادة الرابعة: الأجرة تُدفع وفق جدول الدفعات المتفق عليه.\nالمادة الخامسة: التزامات المستأجر تشمل دفع الأجرة، استخدام الوحدة للسكن فقط، عدم التأجير من الباطن، الحفاظ على الوحدة وعدم القيام بتعديلات بدون موافقة المؤجر.\nالمادة السادسة: التزامات المؤجر تشمل مسؤولية الصيانة والخدمات المشتركة وإصلاح الأعطال الهيكلية.\nالمادة السابعة: الاستلام والتسليم وفق إجراءات الشبكة.\nالمادة الثامنة: مبلغ الضمان يُعاد خلال 30 يومًا بعد انتهاء العقد بعد خصم أي تلفيات.\nالمادة التاسعة: أحكام عامة مثل انتقال الملكية يتم عبر الشبكة.\nالمادة العاشرة: فسخ العقد يتم بشروط التأخير أو عدم الالتزام.\nالمادة الحادية عشرة: انقضاء العقد بانتهاء المدة أو حكم قضائي.\nالمادة الثانية عشرة: آثار انقضاء العقد تشمل إخلاء الوحدة ودفع المستحقات.\nالمادة الثالثة عشرة: تكاليف تسوية الخلافات يتحملها الطرف المماطل.\nالمادة الرابعة عشرة: سريان العقد من تاريخ توقيعه ويجدد وفق الشروط.\nالمادة الخامسة عشرة: القانون الحاكم هو قانون المملكة العربية السعودية ويُعد العقد سندًا تنفيذيًا.\nالمادة السادسة عشرة: الإشعارات والمراسلات تتم عبر الشبكة أو الوسائل النظامية.\nالمادة السابعة عشرة: نسخ العقد إلكترونية وموثقة.\n',
  `privacy_policy` text NOT NULL DEFAULT '\nسياسة الخصوصية: يلتزم الطرفان بالحفاظ على خصوصية البيانات الشخصية وعدم مشاركتها مع جهات خارجية إلا بموافقة خطية من صاحب البيانات أو حسب القوانين والأنظمة السارية في المملكة العربية السعودية. تُستخدم البيانات فقط لأغراض تنفيذ هذا العقد والتزامات الطرفين فيه.\n',
  `pdf_path` varchar(255) DEFAULT NULL,
  `tenant_id` int(11) DEFAULT NULL,
  `admin_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `tenant_id` (`tenant_id`),
  KEY `admin_id` (`admin_id`)
) ENGINE=InnoDB AUTO_INCREMENT=110 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `rental_contracts_details`
--

INSERT DELAYED IGNORE INTO `rental_contracts_details` (`id`, `contract_number`, `contract_type`, `contract_date`, `contract_start`, `contract_end`, `contract_location`, `owner_name`, `owner_nationality`, `owner_id_type`, `owner_id_number`, `owner_email`, `owner_phone`, `owner_address`, `tenant_name`, `tenant_nationality`, `tenant_id_type`, `tenant_id_number`, `tenant_email`, `tenant_phone`, `tenant_address`, `property_national_address`, `property_building_type`, `property_usage`, `property_units_count`, `property_floors_count`, `unit_type`, `unit_number`, `unit_floor_number`, `unit_area`, `unit_furnishing_status`, `unit_ac_units_count`, `unit_ac_type`, `annual_rent`, `periodic_rent_payment`, `rent_payment_cycle`, `rent_payments_count`, `total_contract_value`, `terms_conditions`, `privacy_policy`, `pdf_path`, `tenant_id`, `admin_id`, `created_at`) VALUES
(90, '10155802448 / 1-0', 'جديد', '2024-07-27', '2025-05-05', '2026-05-04', 'جدة', 'احمد علوي هاشم بافقيه', 'المملكة العربية السعودية', 'هوية وطنية', '1002803458', '63321@se.com.sa', '+966500007650', 'جدة مكة, المكرمة', 'وليد حمدي عبد العزيز احمد', 'مصر', 'هوية مقيم', '2577471424', '-', '+966504110261', 'جدة, مكة المكرمة', '3231, 6567, 23451 , الهذاليل شارع 1 الصفا', 'عمارة', 'سكن عائلات', 5, 5, 'استوديو )صغيرة شق َّة)', '2-12', 3, 16.00, ':الت َّأثيث حالة', 1, 'مكيف شباك', 15000.00, 1500.00, '1', 12, 18000.00, '\nالمادة الأولى: البيانات السابقة على التزامات الأطراف تعد جزءًا لا يتجزأ من هذا العقد ومفسّرة ومكمّلة له.\nالمادة الثانية: محل العقد اتفق المؤجر والمستأجر على تأجير الوحدات الإيجارية وفقًا للشروط المذكورة.\nالمادة الثالثة: مدة الإيجار (364 يومًا) تبدأ من تاريخ العقد وتنتهي في التاريخ المحدد.\nالمادة الرابعة: الأجرة تُدفع وفق جدول الدفعات المتفق عليه.\nالمادة الخامسة: التزامات المستأجر تشمل دفع الأجرة، استخدام الوحدة للسكن فقط، عدم التأجير من الباطن، الحفاظ على الوحدة وعدم القيام بتعديلات بدون موافقة المؤجر.\nالمادة السادسة: التزامات المؤجر تشمل مسؤولية الصيانة والخدمات المشتركة وإصلاح الأعطال الهيكلية.\nالمادة السابعة: الاستلام والتسليم وفق إجراءات الشبكة.\nالمادة الثامنة: مبلغ الضمان يُعاد خلال 30 يومًا بعد انتهاء العقد بعد خصم أي تلفيات.\nالمادة التاسعة: أحكام عامة مثل انتقال الملكية يتم عبر الشبكة.\nالمادة العاشرة: فسخ العقد يتم بشروط التأخير أو عدم الالتزام.\nالمادة الحادية عشرة: انقضاء العقد بانتهاء المدة أو حكم قضائي.\nالمادة الثانية عشرة: آثار انقضاء العقد تشمل إخلاء الوحدة ودفع المستحقات.\nالمادة الثالثة عشرة: تكاليف تسوية الخلافات يتحملها الطرف المماطل.\nالمادة الرابعة عشرة: سريان العقد من تاريخ توقيعه ويجدد وفق الشروط.\nالمادة الخامسة عشرة: القانون الحاكم هو قانون المملكة العربية السعودية ويُعد العقد سندًا تنفيذيًا.\nالمادة السادسة عشرة: الإشعارات والمراسلات تتم عبر الشبكة أو الوسائل النظامية.\nالمادة السابعة عشرة: نسخ العقد إلكترونية وموثقة.\n', '\nسياسة الخصوصية: يلتزم الطرفان بالحفاظ على خصوصية البيانات الشخصية وعدم مشاركتها مع جهات خارجية إلا بموافقة خطية من صاحب البيانات أو حسب القوانين والأنظمة السارية في المملكة العربية السعودية. تُستخدم البيانات فقط لأغراض تنفيذ هذا العقد والتزامات الطرفين فيه.\n', 'uploads\\5f3f490972379d163a5c4e2b2d055d27', 3, 2, '2025-05-31 18:45:54'),
(91, '10077966178 / 1-0', 'جديد', '2024-08-26', '2025-05-02', '2026-05-01', 'جدة', 'امال علوي هاشم بافقيه', 'المملكة العربية السعودية', 'هوية وطنية', '1002803441', '63321@se.com.sa', '+966500007650', 'جدة مكة, المكرمة', 'البراء الشيخ بابكر البدوى', 'السودان', 'هوية مقيم', '2526222688', '-', '+966552624950', 'جدة, مكة المكرمة', '6924, 2932, 23452, عبدالقدوس ابن', 'عمارة', 'سكن عائلات', 3, 3, 'استوديو )صغيرة شق َّة)', '2 - 1', 1, 12.00, ':الت َّأثيث حالة', 1, 'مكيف شباك', 0.00, 1500.00, '1', 12, 18000.00, '\nالمادة الأولى: البيانات السابقة على التزامات الأطراف تعد جزءًا لا يتجزأ من هذا العقد ومفسّرة ومكمّلة له.\nالمادة الثانية: محل العقد اتفق المؤجر والمستأجر على تأجير الوحدات الإيجارية وفقًا للشروط المذكورة.\nالمادة الثالثة: مدة الإيجار (364 يومًا) تبدأ من تاريخ العقد وتنتهي في التاريخ المحدد.\nالمادة الرابعة: الأجرة تُدفع وفق جدول الدفعات المتفق عليه.\nالمادة الخامسة: التزامات المستأجر تشمل دفع الأجرة، استخدام الوحدة للسكن فقط، عدم التأجير من الباطن، الحفاظ على الوحدة وعدم القيام بتعديلات بدون موافقة المؤجر.\nالمادة السادسة: التزامات المؤجر تشمل مسؤولية الصيانة والخدمات المشتركة وإصلاح الأعطال الهيكلية.\nالمادة السابعة: الاستلام والتسليم وفق إجراءات الشبكة.\nالمادة الثامنة: مبلغ الضمان يُعاد خلال 30 يومًا بعد انتهاء العقد بعد خصم أي تلفيات.\nالمادة التاسعة: أحكام عامة مثل انتقال الملكية يتم عبر الشبكة.\nالمادة العاشرة: فسخ العقد يتم بشروط التأخير أو عدم الالتزام.\nالمادة الحادية عشرة: انقضاء العقد بانتهاء المدة أو حكم قضائي.\nالمادة الثانية عشرة: آثار انقضاء العقد تشمل إخلاء الوحدة ودفع المستحقات.\nالمادة الثالثة عشرة: تكاليف تسوية الخلافات يتحملها الطرف المماطل.\nالمادة الرابعة عشرة: سريان العقد من تاريخ توقيعه ويجدد وفق الشروط.\nالمادة الخامسة عشرة: القانون الحاكم هو قانون المملكة العربية السعودية ويُعد العقد سندًا تنفيذيًا.\nالمادة السادسة عشرة: الإشعارات والمراسلات تتم عبر الشبكة أو الوسائل النظامية.\nالمادة السابعة عشرة: نسخ العقد إلكترونية وموثقة.\n', '\nسياسة الخصوصية: يلتزم الطرفان بالحفاظ على خصوصية البيانات الشخصية وعدم مشاركتها مع جهات خارجية إلا بموافقة خطية من صاحب البيانات أو حسب القوانين والأنظمة السارية في المملكة العربية السعودية. تُستخدم البيانات فقط لأغراض تنفيذ هذا العقد والتزامات الطرفين فيه.\n', 'uploads\\17e1512e4050069ba1b32ac8ba7555c1', 6, 4, '2025-05-31 18:49:13'),
(109, '10077966178 / 1-0', 'جديد', '2025-05-31', '2025-05-31', '2026-05-31', 'جدة', 'امال علوي هاشم بافقيه', 'المملكة العربية السعودية', 'هوية وطنية', '1002803441', '63321@se.com.sa', '+966500007650', 'جدة مكة, المكرمة', 'البراء الشيخ بابكر البدوى', 'السودان', 'هوية مقيم', '2526222688', '-', '+966552624950', 'جدة, مكة المكرمة', '6924, 2932, 23452, عبدالقدوس ابن', 'عمارة', 'سكن عائلات', 3, 3, 'استوديو )صغيرة شق َّة)', '2 - 1', 1, 12.00, ':الت َّأثيث حالة', 1, 'مكيف شباك', 15600.00, 1300.00, 'شهري', 12, 15600.00, '\nالمادة الأولى: البيانات السابقة على التزامات الأطراف تعد جزءًا لا يتجزأ من هذا العقد ومفسّرة ومكمّلة له.\nالمادة الثانية: محل العقد اتفق المؤجر والمستأجر على تأجير الوحدات الإيجارية وفقًا للشروط المذكورة.\nالمادة الثالثة: مدة الإيجار (364 يومًا) تبدأ من تاريخ العقد وتنتهي في التاريخ المحدد.\nالمادة الرابعة: الأجرة تُدفع وفق جدول الدفعات المتفق عليه.\nالمادة الخامسة: التزامات المستأجر تشمل دفع الأجرة، استخدام الوحدة للسكن فقط، عدم التأجير من الباطن، الحفاظ على الوحدة وعدم القيام بتعديلات بدون موافقة المؤجر.\nالمادة السادسة: التزامات المؤجر تشمل مسؤولية الصيانة والخدمات المشتركة وإصلاح الأعطال الهيكلية.\nالمادة السابعة: الاستلام والتسليم وفق إجراءات الشبكة.\nالمادة الثامنة: مبلغ الضمان يُعاد خلال 30 يومًا بعد انتهاء العقد بعد خصم أي تلفيات.\nالمادة التاسعة: أحكام عامة مثل انتقال الملكية يتم عبر الشبكة.\nالمادة العاشرة: فسخ العقد يتم بشروط التأخير أو عدم الالتزام.\nالمادة الحادية عشرة: انقضاء العقد بانتهاء المدة أو حكم قضائي.\nالمادة الثانية عشرة: آثار انقضاء العقد تشمل إخلاء الوحدة ودفع المستحقات.\nالمادة الثالثة عشرة: تكاليف تسوية الخلافات يتحملها الطرف المماطل.\nالمادة الرابعة عشرة: سريان العقد من تاريخ توقيعه ويجدد وفق الشروط.\nالمادة الخامسة عشرة: القانون الحاكم هو قانون المملكة العربية السعودية ويُعد العقد سندًا تنفيذيًا.\nالمادة السادسة عشرة: الإشعارات والمراسلات تتم عبر الشبكة أو الوسائل النظامية.\nالمادة السابعة عشرة: نسخ العقد إلكترونية وموثقة.\n', '\nسياسة الخصوصية: يلتزم الطرفان بالحفاظ على خصوصية البيانات الشخصية وعدم مشاركتها مع جهات خارجية إلا بموافقة خطية من صاحب البيانات أو حسب القوانين والأنظمة السارية في المملكة العربية السعودية. تُستخدم البيانات فقط لأغراض تنفيذ هذا العقد والتزامات الطرفين فيه.\n', '/uploads/1748721647997-763505646.pdf', 11, 4, '2025-05-31 20:00:48');

-- --------------------------------------------------------

--
-- Table structure for table `rental_contract_extensions`
--

DROP TABLE IF EXISTS `rental_contract_extensions`;
CREATE TABLE IF NOT EXISTS `rental_contract_extensions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `contract_id` int(11) NOT NULL,
  `extended_by` int(11) NOT NULL,
  `extension_start` date NOT NULL,
  `extension_end` date NOT NULL,
  `extension_days` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `contract_id` (`contract_id`),
  KEY `extended_by` (`extended_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `reviews`
--

DROP TABLE IF EXISTS `reviews`;
CREATE TABLE IF NOT EXISTS `reviews` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` varchar(255) NOT NULL,
  `rating` int(11) NOT NULL,
  `comment` text DEFAULT NULL,
  `visible` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `reviews`
--

INSERT DELAYED IGNORE INTO `reviews` (`id`, `user_id`, `rating`, `comment`, `visible`, `created_at`) VALUES
(1, 'tenant1', 4, '', 1, '2025-05-30 19:27:07'),
(2, 'tenant1', 4, 'هلوووو', 1, '2025-05-30 19:29:33'),
(3, 'tenant1', 4, 'غصغصغ', 1, '2025-05-30 19:31:08'),
(4, 'tenant1', 5, 'غسغسغصل', 1, '2025-05-30 19:33:41'),
(5, 'tenant1', 2, 'لغىغبغرر', 1, '2025-05-30 19:33:58'),
(6, 'tenant1', 5, 'ل٤لر٢سلوفب١س', 1, '2025-05-30 19:35:44'),
(7, 'tenant1', 5, 'هصاصلصب٢بب', 1, '2025-05-30 20:18:39'),
(8, 'tenant1', 5, 'ل١غ٢٧٢ب١ف١٦٢ف', 1, '2025-05-30 20:18:45'),
(9, 'tenant1', 2, '', 1, '2025-05-30 20:19:42'),
(10, 'tenant1', 4, 'خاهلىترؤ', 1, '2025-05-30 20:19:49'),
(11, 'tenant1', 3, 'لي٥قسش', 1, '2025-05-30 20:21:29'),
(12, 'tenant1', 2, 'لي٥غبيي', 1, '2025-05-30 20:26:10'),
(13, 'tenant1', 5, 'هو بس بل عن مع ب ثم قي', 1, '2025-05-30 20:26:19'),
(14, 'tenant1', 1, 'اه٨يس٤ر غ', 1, '2025-05-30 20:26:56'),
(15, 'tenant1', 5, 'عسغسغصلش٦سف', 1, '2025-05-30 20:27:03'),
(16, 'tenant1', 5, 'فصغصغصغسبضبب', 1, '2025-05-30 20:27:10'),
(17, 'tenant1', 5, '٦ص٦سلصغسف٢رصف', 1, '2025-05-30 20:27:19'),
(18, 'tenant1', 5, 'لسفسغسغسفسفسف', 1, '2025-05-30 20:27:26'),
(19, 'tenant1', 5, 'فشغسغسغف', 1, '2025-05-30 20:27:35'),
(20, 'tenant1', 5, 'فسغسغسلسبسفس٥', 1, '2025-05-30 20:27:42'),
(21, 'tenant1', 5, 'فس٦س٦صلسلشلص٦٦', 1, '2025-05-30 20:27:49'),
(22, 'tenant1', 2, 'و و. اراىابغبب', 1, '2025-05-30 23:34:23'),
(23, 'tenant1', 5, 'شكرررررررا خدمه ممتاز وروووووووووعه ❤️❤️❤️❤️', 1, '2025-05-31 00:06:20'),
(24, 'tenant_test', 5, 'خدمه رائعه', 1, '2025-05-31 20:23:38'),
(25, 'tenant_test', 5, 'ولا اروووووع', 1, '2025-05-31 20:36:14'),
(26, 'tenant_test', 5, 'yesssss', 1, '2025-05-31 22:43:58');

-- --------------------------------------------------------

--
-- Table structure for table `review_permissions`
--

DROP TABLE IF EXISTS `review_permissions`;
CREATE TABLE IF NOT EXISTS `review_permissions` (
  `admin_id` varchar(255) NOT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`admin_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `review_points`
--

DROP TABLE IF EXISTS `review_points`;
CREATE TABLE IF NOT EXISTS `review_points` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` varchar(255) NOT NULL,
  `points` int(11) NOT NULL,
  `source` varchar(100) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `review_points`
--

INSERT DELAYED IGNORE INTO `review_points` (`id`, `user_id`, `points`, `source`, `created_at`) VALUES
(1, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 19:27:07'),
(2, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 19:29:33'),
(3, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 19:31:08'),
(4, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 19:33:41'),
(5, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 19:33:58'),
(6, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 19:35:44'),
(7, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:18:39'),
(8, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:18:45'),
(9, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:19:42'),
(10, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:19:49'),
(11, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:21:29'),
(12, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:26:10'),
(13, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:26:19'),
(14, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:26:56'),
(15, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:27:03'),
(16, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:27:10'),
(17, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:27:19'),
(18, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:27:26'),
(19, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:27:35'),
(20, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:27:42'),
(21, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 20:27:49'),
(22, 'tenant1', 10, 'إرسال تقييم', '2025-05-30 23:34:23'),
(23, 'tenant1', 10, 'إرسال تقييم', '2025-05-31 00:06:20'),
(24, 'tenant_test', 10, 'إرسال تقييم', '2025-05-31 20:23:38'),
(25, 'tenant_test', 10, 'إرسال تقييم', '2025-05-31 20:36:14'),
(26, 'tenant_test', 10, 'إرسال تقييم', '2025-05-31 22:43:58');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` varchar(50) NOT NULL,
  `token` varchar(255) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `user_type` enum('super','admin','user') NOT NULL DEFAULT 'user',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `fcm_token` text DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT DELAYED IGNORE INTO `users` (`id`, `user_id`, `token`, `name`, `user_type`, `created_at`, `fcm_token`, `created_by`) VALUES
(1, 'superadmin', 'super123token', 'الإدارة العليا', 'super', '2025-05-28 10:20:24', NULL, NULL),
(2, 'adminuser', 'admin123token', 'الإدارة الوسطى', 'admin', '2025-05-28 10:20:24', NULL, NULL),
(3, 'tenantuser', 'user123token', 'مستأجر', 'user', '2025-05-28 10:20:24', 'cdHl0Ii9SKuuqi8_1lss8k:APA91bE-OiLxfLNR3CgJAbhe9Ur7LzOk_of0EfL54BC6iPr2ShyDFOT6kpGdql9oN5CfarQ_QygttoKSrF7WBNgSc-tfkc2o2QKTtMp_4-519Q0Wu0pnxQw', NULL),
(4, 'admin1', 'token_admin1', 'الإدارة الوسطى 1', 'admin', '2025-05-29 20:29:31', NULL, NULL),
(5, 'admin2', 'token_admin2', 'الإدارة الوسطى 2', 'admin', '2025-05-29 20:29:31', NULL, NULL),
(6, 'tenant1', 'token_tenant1', 'مستأجر 1', 'user', '2025-05-29 20:29:48', 'dzwFIGL4RZmv72ADzfQa9c:APA91bHJjjnMfk_c5ouu6WoB9x2cCvNt1ZRTZ9kRea7Ku5XsCzV5yjWORkwOsGzRBpu-z7mNc6DYKuSvZSfKOnWVBsSB_lbcjA1BH3964hB8Au-aDKJD17M', NULL),
(8, 'admin_test', 'ade78da72db62fe9e533dc1be97804bc8edde2e8a26b4c847fabcb8f2fb298d5', 'مالك تجريبي', 'admin', '2025-05-31 19:45:46', NULL, NULL),
(9, 'admin_te1st', '8487739417116a83fbf81e075636aa8da3b7ef8f3196a163b4fd8a8ffe122bd1', 'مالك تجريبي', 'admin', '2025-05-31 19:46:33', NULL, NULL),
(10, 'admin_te12st', '544945a5229641fa25f1ae916452249fcd12d11c3f08e8c90b36d54be0c33c51', 'مالك تجريبي', 'admin', '2025-05-31 19:49:59', NULL, NULL),
(11, 'tenant_test', '2f8c9398a95c998417e3bb93ec54aa5487fb64c4fd1654b78fdb6b3a16f6076e', 'مستأجر تجريبي', 'user', '2025-05-31 19:52:52', 'fPfWaLh0Sh6mjB4W5Yv0B5:APA91bHP-tu1MVEQdaU16WeUkqdpxxqfPb9N4ryAVBBPQQZo4KpRSY_3FSqwiN3bgHXs_sULxlSiofZJEqrtDR6Z9F86iGKN7-L35SlyGqBM1WVnF-Lym8Y', 2);

--
-- Triggers `users`
--
DROP TRIGGER IF EXISTS `auto_assign_services_to_admin`;
DELIMITER $$
CREATE TRIGGER `auto_assign_services_to_admin` AFTER INSERT ON `users` FOR EACH ROW BEGIN
  IF NEW.user_type = 'admin' THEN
    INSERT INTO admin_service_visibility (admin_id, service_id, is_enabled)
    SELECT NEW.id, s.id, 1
    FROM dynamic_services s
    WHERE s.id IN (1,2,3,4,5,6,7,8,9) AND s.is_active = 1;
  END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `user_tokens`
--

DROP TABLE IF EXISTS `user_tokens`;
CREATE TABLE IF NOT EXISTS `user_tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `token` varchar(255) NOT NULL,
  `permissions` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`permissions`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  KEY `created_by` (`created_by`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `user_tokens`
--

INSERT DELAYED IGNORE INTO `user_tokens` (`id`, `token`, `permissions`, `created_at`, `created_by`) VALUES
(1, '2f8c9398a95c998417e3bb93ec54aa5487fb64c4fd1654b78fdb6b3a16f6076e', '{\"chat\":true,\"payments\":true}', '2025-05-31 19:52:52', 2);

--
-- Constraints for dumped tables
--

--
-- Constraints for table `admin_subscriptions`
--
ALTER TABLE `admin_subscriptions`
  ADD CONSTRAINT `admin_subscriptions_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `admin_subscription_extensions`
--
ALTER TABLE `admin_subscription_extensions`
  ADD CONSTRAINT `admin_subscription_extensions_ibfk_1` FOREIGN KEY (`subscription_id`) REFERENCES `admin_subscriptions` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `admin_subscription_extensions_ibfk_2` FOREIGN KEY (`extended_by`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `admin_tokens`
--
ALTER TABLE `admin_tokens`
  ADD CONSTRAINT `admin_tokens_ibfk_1` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `chat_rooms`
--
ALTER TABLE `chat_rooms`
  ADD CONSTRAINT `chat_rooms_ibfk_1` FOREIGN KEY (`contract_id`) REFERENCES `rental_contracts_details` (`id`),
  ADD CONSTRAINT `chat_rooms_ibfk_2` FOREIGN KEY (`tenant_user_id`) REFERENCES `users` (`user_id`),
  ADD CONSTRAINT `chat_rooms_ibfk_3` FOREIGN KEY (`admin_user_id`) REFERENCES `users` (`user_id`);

--
-- Constraints for table `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`contract_id`) REFERENCES `rental_contracts_details` (`id`),
  ADD CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`sender_id`) REFERENCES `users` (`user_id`),
  ADD CONSTRAINT `messages_ibfk_3` FOREIGN KEY (`receiver_id`) REFERENCES `users` (`user_id`),
  ADD CONSTRAINT `messages_ibfk_4` FOREIGN KEY (`chat_room_id`) REFERENCES `chat_rooms` (`id`);

--
-- Constraints for table `noise_complaints`
--
ALTER TABLE `noise_complaints`
  ADD CONSTRAINT `noise_complaints_ibfk_1` FOREIGN KEY (`tenant_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `noise_complaints_ibfk_2` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `payments`
--
ALTER TABLE `payments`
  ADD CONSTRAINT `payments_ibfk_1` FOREIGN KEY (`contract_id`) REFERENCES `rental_contracts_details` (`id`);

--
-- Constraints for table `payment_alert_settings`
--
ALTER TABLE `payment_alert_settings`
  ADD CONSTRAINT `payment_alert_settings_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `rental_contracts`
--
ALTER TABLE `rental_contracts`
  ADD CONSTRAINT `rental_contracts_ibfk_1` FOREIGN KEY (`tenant_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `rental_contracts_details`
--
ALTER TABLE `rental_contracts_details`
  ADD CONSTRAINT `rental_contracts_details_ibfk_1` FOREIGN KEY (`tenant_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `rental_contracts_details_ibfk_2` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `rental_contract_extensions`
--
ALTER TABLE `rental_contract_extensions`
  ADD CONSTRAINT `rental_contract_extensions_ibfk_1` FOREIGN KEY (`contract_id`) REFERENCES `rental_contracts` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `rental_contract_extensions_ibfk_2` FOREIGN KEY (`extended_by`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `user_tokens`
--
ALTER TABLE `user_tokens`
  ADD CONSTRAINT `user_tokens_ibfk_1` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL;
SET FOREIGN_KEY_CHECKS=1;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
