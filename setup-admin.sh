#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"
cp -n .env.example .env 2>/dev/null || true
read -s -p "Nhập mật khẩu Admin: " ADMIN_PASSWORD
echo
if [ -z "$ADMIN_PASSWORD" ]; then echo "Mật khẩu không được để trống"; exit 1; fi
sed -i "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$ADMIN_PASSWORD/" .env
if ! grep -q '^DATA_ENCRYPTION_KEY=' .env || [ -z "$(cut -d= -f2- .env)" ]; then
  KEY="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
  sed -i "s/^DATA_ENCRYPTION_KEY=.*/DATA_ENCRYPTION_KEY=$KEY/" .env
fi
chmod 600 .env
echo "Đã tạo .env an toàn."
