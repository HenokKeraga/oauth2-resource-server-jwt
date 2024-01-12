package com.example.resourceserver.controller;

import com.example.resourceserver.model.Student;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class StudentController {

    @GetMapping("/students")
    public ResponseEntity<List<Student>> getAllStudent(Authentication authentication) {
        return ResponseEntity
                .ok()
                .body(List.of(new Student(1, "Henok", "computer"),new Student(2,"Woin","Accounting")));
    }
}
