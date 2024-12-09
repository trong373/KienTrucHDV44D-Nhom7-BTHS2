package com.example.bths2.utils;


import io.jsonwebtoken.*;
import java.util.Date;

public class JwtUtil {
    private static final String SECRET_KEY = "1234";
    private static final long EXPIRATION_TIME = 3600000;
    /**
     * Phương thức tạo JWT.
     * @param username - Tên người dùng cần mã hóa trong token.
     * @return String - Token đã mã hóa.
     */
    @SuppressWarnings("deprecation")
    public static String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username) // Đặt giá trị chính (username)
                .setIssuedAt(new Date()) // Thời gian tạo token
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // Thời gian hết hạn
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // Mã hóa với thuật toán HS256
                .compact(); // Hoàn thiện token
    }

    /**
     * Phương thức xác thực và giải mã JWT.
     * @param token - Token được gửi từ client.
     * @return Claims - Dữ liệu chứa trong token (username, thời gian, ...)
     * @throws Exception - Ném lỗi nếu token không hợp lệ hoặc hết hạn.
     */
    @SuppressWarnings("deprecation")
    public static Claims validateToken(String token) throws Exception {
        try {
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY) 
                    .parseClaimsJws(token) 
                    .getBody(); 
        } catch (ExpiredJwtException e) {
            throw new Exception("Token đã hết hạn!");
        } catch (UnsupportedJwtException e) {
            throw new Exception("Token không được hỗ trợ!");
        } catch (MalformedJwtException e) {
            throw new Exception("Token không hợp lệ!");
        } catch (SignatureException e) {
            throw new Exception("Chữ ký token không hợp lệ!");
        } catch (IllegalArgumentException e) {
            throw new Exception("Token rỗng!");
        }
    }
}
