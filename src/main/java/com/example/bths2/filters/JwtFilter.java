package com.example.bths2.filters;



import com.example.bths2.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    /**
     * Phương thức xử lý mỗi yêu cầu HTTP để kiểm tra token.
     * @param request - Yêu cầu HTTP từ client.
     * @param response - Phản hồi HTTP cho client.
     * @param filterChain - Chuỗi filter tiếp theo.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Lấy token từ header Authorization
        String authHeader = request.getHeader("Authorization");

        // Kiểm tra token có tồn tại và bắt đầu bằng "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token is required!");
            return;
        }

        String token = authHeader.substring(7); // Loại bỏ "Bearer " để lấy token thật sự

        try {
            // Xác thực token
            Claims claims = JwtUtil.validateToken(token);
            request.setAttribute("username", claims.getSubject()); // Lưu username từ token vào request
            filterChain.doFilter(request, response); // Tiếp tục xử lý request
        } catch (Exception e) {
            // Nếu token không hợp lệ, trả lỗi 401
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(e.getMessage());
        }
    }
}
