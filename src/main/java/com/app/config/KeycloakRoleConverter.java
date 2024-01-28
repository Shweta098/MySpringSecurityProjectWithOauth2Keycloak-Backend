package com.app.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

//Keycloak server will return an access token which will contain role/authorization information of client or end user
//KeycloakRoleConverter will convert those authorities/roles to spring framework understandable language
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>>{
	//Converter will accept the JWT token from authorization server and extranct the roles info and send back a list of granted authority.
		//because my spring framework will only understand rols/authorities if in the form of granted authorities
	
	 @Override
	    public Collection<GrantedAuthority> convert(Jwt jwt) {
	        Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");

	        if (realmAccess == null || realmAccess.isEmpty()) {
	            return new ArrayList<>();
	        }

	        Collection<GrantedAuthority> returnValue = ((List<String>) realmAccess.get("roles"))
	                .stream().map(roleName -> "ROLE_" + roleName)
	                .map(SimpleGrantedAuthority::new)
	                .collect(Collectors.toList());

	        return returnValue;
	    }

}
