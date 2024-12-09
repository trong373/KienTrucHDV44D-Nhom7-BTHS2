package com.example.bths2.controller;


import com.example.bths2.model.User;
import com.example.bths2.repositories.UserRepository;
import com.example.bths2.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;



@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    /**
     * API Login - Đăng nhập người dùng.
     * @param loginRequest - Đối tượng chứa username và password từ client.
     * @return ResponseEntity<?> - Trả về token JWT nếu thành công, hoặc thông báo lỗi nếu thất bại.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest) {
        // Tìm người dùng theo username
        User user = userRepository.findByUserName(loginRequest.getUserName());

        // Kiểm tra username và password
        if (user == null || !user.getPassword().equals(loginRequest.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // Sinh token và lưu vào cơ sở dữ liệu
        String token = JwtUtil.generateToken(user.getUserName());
        user.setToken(token);
        userRepository.save(user);

        return ResponseEntity.ok(token);
    }

    /**
     * API Verify Token - Xác thực token từ client.
     * @param token - Token JWT gửi qua query parameter.
     * @return ResponseEntity<?> - Trả về thông báo nếu token hợp lệ hoặc lỗi nếu không hợp lệ.
     */
    @GetMapping("/verify")
    public ResponseEntity<?> verifyToken(@RequestParam String token) {
        try {
            // Xác thực token
            JwtUtil.validateToken(token);
            return ResponseEntity.ok("Token is valid");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
}
