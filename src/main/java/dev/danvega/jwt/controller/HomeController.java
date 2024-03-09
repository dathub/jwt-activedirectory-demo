package dev.danvega.jwt.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home(Principal principal) {
        return "Hello, " + principal.getName();
    }

    @GetMapping("/secret")
    public String secret(Principal principal) {
        return "This is a secret, " + principal.getName();
    }

    @GetMapping("/topsecret")
    public String topsecret(Principal principal) {
        return "This is a top secret, " + principal.getName();
    }
}
