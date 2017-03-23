package tn.cyn.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.GenericFilterBean;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

public class JWTFilter extends GenericFilterBean {

	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String AUTHORITIES_KEY = "roles";

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE");
		response.setHeader("Access-Control-Allow-Origin", "*");
		response.setHeader("Access-Control-Expose-Headers" ,"Authorization");
		String authHeader = request.getHeader(AUTHORIZATION_HEADER);
		response.setHeader("Access-Control-Allow-Headers",
				"Origin, X-Requested-With, ,Content-Type, Accept, Access-Control-Allow-Headers, Authorization," + authHeader);
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			((HttpServletResponse) res).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Authorization header.");
		} else {
			try {
				String token = authHeader.substring(7);
/*
				// HttpServletResponse response = (HttpServletResponse) res;
				// response.setHeader("Access-Control-Allow-Methods", "POST,
				// GET"); // also added header to allow POST, GET method to be
				// available
				// response.setHeader("Access-Control-Allow-Origin", "*"); //
				// also added header to allow cross domain request for any
				// domain
				
				// ---------------------------------------------------------------//
				HttpServletResponse response = (HttpServletResponse) res;
				response.setHeader("Access-Control-Allow-Origin", "*");
				response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE");
				response.setHeader("Access-Control-Max-Age", "3600");
				response.setHeader("Access-Control-Allow-Headers",
						"Origin, X-Requested-With, Content-Type, Accept, " + authHeader);
				// ---------------------------------------------------------------//
				*/
				Claims claims = Jwts.parser().setSigningKey("secretkey").parseClaimsJws(token).getBody();
				request.setAttribute("claims", claims);
				SecurityContextHolder.getContext().setAuthentication(getAuthentication(claims));
				filterChain.doFilter(req, res);
			} catch (SignatureException e) {
				((HttpServletResponse) res).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
			}

		}
	}

	private Authentication getAuthentication(Claims claims) {
		List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
		List<String> roles = (List<String>) claims.get(AUTHORITIES_KEY);
		for (String role : roles) {
			authorities.add(new SimpleGrantedAuthority(role));
		}
		User principal = new User(claims.getSubject(), "", authorities);
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				principal, "", authorities);
		return usernamePasswordAuthenticationToken;
	}
}
