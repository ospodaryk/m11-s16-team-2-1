package com.softserve.itacademy.controller;

import com.softserve.itacademy.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    private final UserService userService;
    public HomeController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping({"/", "home"})
    @PreAuthorize("hasAuthority('ADMIN')")
    public String home(Model model) {
        model.addAttribute("users", userService.getAll());
        return "home";
    }

    @GetMapping("/form-login")
    public String login() {
        return "form-login";
    }
}