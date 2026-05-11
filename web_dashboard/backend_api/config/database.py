# /home/bk_ids/bk-ids/web_dashboard/backend_api/config/database.py

import mysql.connector
import os
import logging

logger = logging.getLogger(__name__)

def get_db_connection():
    """
    Kết nối Cơ sở dữ liệu thông minh (Dual-Connect Strategy)
    Tự động tương thích với cả API Server và Sensor Host-mode.
    """
    db_port = int(os.environ.get('MYSQL_PORT', 3306))
    db_user = os.environ.get('MYSQL_USER')
    db_pass = os.environ.get('MYSQL_PASSWORD')
    db_name = os.environ.get('MYSQL_DATABASE')

    if not all([db_user, db_pass, db_name]):
        logger.error(" LỖI BẢO MẬT: Thiếu thông tin cấu hình DB.")
        return None

    # BƯỚC 1: Thử kết nối thông qua mạng ảo Docker (Dành riêng cho API Server)
    try:
        return mysql.connector.connect(
            host='bkids_mysql', 
            port=db_port, user=db_user, password=db_pass, database=db_name, 
            connect_timeout=2, auth_plugin='mysql_native_password'
        )
    except:
        # BƯỚC 2: Nếu thất bại, thử kết nối qua Localhost (Dành riêng cho Lõi Sensor Host-mode)
        try:
            return mysql.connector.connect(
                host='127.0.0.1', 
                port=db_port, user=db_user, password=db_pass, database=db_name, 
                connect_timeout=2, auth_plugin='mysql_native_password'
            )
        except Exception as e:
            logger.error(f" KHÔNG THỂ KẾT NỐI DATABASE CẢ 2 CÁCH: {e}")
            return None

def get_direct_db_connection():
    return get_db_connection()