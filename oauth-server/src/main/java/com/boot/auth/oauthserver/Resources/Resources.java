package com.boot.auth.oauthserver.Resources;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@RestController
public class Resources {

    @GetMapping("/api/rosetta")
    @PreAuthorize("hasAuthority('ROSETTA_ADMIN')")
    public String getRosettaData(Authentication authentication){
        System.out.println(((UserDetails)authentication.getPrincipal()).getUsername());
        return "ROSETTA";
    }
}
