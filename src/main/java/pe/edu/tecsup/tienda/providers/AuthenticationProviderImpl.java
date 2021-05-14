package pe.edu.tecsup.tienda.providers;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import pe.edu.tecsup.tienda.repositories.UsuarioRepository;

@Component
public class AuthenticationProviderImpl implements AuthenticationProvider  {

	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	
	@Override
	public Authentication authenticate(Authentication authentication) 
			throws AuthenticationException {
		
		String username = authentication.getName();
		String password = (String) authentication.getCredentials();
        
		UserDetails userDetails = usuarioRepository.loadUserByUsername(username);
		if(userDetails == null)
			throw new UsernameNotFoundException("Usuario NOO encontrado");
		
		if(!passwordEncoder.matches(password, userDetails.getPassword())){
			throw new BadCredentialsException("Usuario y/o clave invalido");
		}
		
		Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
		
		return new UsernamePasswordAuthenticationToken(userDetails, password, authorities);

	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return true;
	}

}
