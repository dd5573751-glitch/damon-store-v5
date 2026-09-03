DAMON STORE V5
- Không seed sản phẩm. Shop bắt đầu trống.
- Admin thêm sản phẩm và nhiều KEY cho từng sản phẩm.
- User mua sẽ nhận 1 KEY và KEY hiện trong lịch sử mua.
- API public chỉ trả số lượng KEY còn, không trả KEY.
- Username/password, seller approval, topup ranking.
- Seller được giảm 15%; người đứng #1 tháng trước được giảm 8%.
- Admin credentials chỉ đặt trong .env, không đưa lên frontend/GitHub.
- JSON data phù hợp demo/nhỏ; production nên dùng database + persistent storage.

SECURITY
- data.json is encrypted at rest with AES-256-GCM.
- Public product API never returns KEY values.
- Rate limits are applied globally and more strictly to auth, purchase, and admin routes.
- Real volumetric DDoS needs a CDN/WAF/reverse proxy; app rate limiting alone cannot stop network-level DDoS.
- Never upload .env or DATA_ENCRYPTION_KEY to GitHub.

CARD TOPUP
- Publicly visible DuyMod Game card discounts checked on 2026-09-02: Garena 18%, Vinaphone 25.8%, Viettel 27.6%.
- The full denomination table redirects to login, so no private/login-only pricing was copied or guessed.
- Admin credentials are not bundled into this archive. Run ./setup-admin.sh and enter the admin password locally.
