# /home/ids/bk_ids/bk-ids/web_dashboard/backend_api/config/database.py

import mysql.connector
import os
import logging

logger = logging.getLogger(__name__)

def get_db_connection():
    """
    Kết nối Cơ sở dữ liệu thông minh (Dual-Connect Strategy)
    Tự động tương thích với cả API Server và Sensor Host-mode.
    """
    db_host = os.environ.get('MYSQL_HOST', 'bkids_mysql')
    db_port = int(os.environ.get('MYSQL_PORT', 3306))
    db_user = os.environ.get('MYSQL_USER')
    db_pass = os.environ.get('MYSQL_PASSWORD')
    db_name = os.environ.get('MYSQL_DATABASE')

    if not all([db_user, db_pass, db_name]):
        logger.error(" LỖI BẢO MẬT: Thiếu thông tin cấu hình DB.")
        return None

    # BƯỚC 1: Thử kết nối thông qua mạng ảo Docker
    try:
        return mysql.connector.connect(
            host=db_host,
            port=db_port, user=db_user, password=db_pass, database=db_name,
            connect_timeout=3, auth_plugin='mysql_native_password'
        )
    except Exception as e1:
        logger.warning(f"Không kết nối được qua {db_host}: {e1}")
        # BƯỚC 2: Fallback qua localhost
        try:
            return mysql.connector.connect(
                host='127.0.0.1',
                port=db_port, user=db_user, password=db_pass, database=db_name,
                connect_timeout=3, auth_plugin='mysql_native_password'
            )
        except Exception as e2:
            logger.error(f" KHÔNG THỂ KẾT NỐI DATABASE CẢ 2 CÁCH: host={db_host} err={e1}, localhost err={e2}")
            return None

def get_direct_db_connection():
    return get_db_connection()
