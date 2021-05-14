package pe.edu.tecsup.tienda.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter  {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new PasswordEncoder() {	// No encriptado, Texto Plano
			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return rawPassword.toString().equals(encodedPassword);
			}
			@Override
			public String encode(CharSequence rawPassword) {
				return rawPassword.toString();
			}
		};
//	    return new BCryptPasswordEncoder();	// Algoritmo BCrypt
	}
	
	/* Part 1 
	@Bean
	@Override
	public UserDetailsService userDetailsServiceBean() throws Exception {

		List<UserDetails> users = new ArrayList<UserDetails>();

		users.add(User.withUsername("jgomez").password("123456").roles("USER").build());
		
		users.add(User.withUsername("user").password("user").roles("USER").build());
		
		users.add(User.withUsername("admin").password("admin").roles("USER", "ADMIN").build());

		return new InMemoryUserDetailsManager(users);
	} */
	
	/* Parte 2
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	public void configureAuth(AuthenticationManagerBuilder auth) 
			throws Exception{
		auth.userDetailsService(userDetailsService);
	} */
	
	/*  Parte 3
	@Autowired
	private AuthenticationProvider authenticationProvider;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider);
	}
	*/

	@Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
        // Configure authorizations
//	        .authorizeRequests()
//	        .antMatchers("/" /*, "/**"*/).permitAll()
//	        .antMatchers("/home/**").authenticated()
//	        .antMatchers("/admin/**").hasAnyAuthority("Administrador")
//    	.and()
        // Change login
        	.formLogin()
        	.loginPage("/login")
        	.loginProcessingUrl("/authenticate")
        	.defaultSuccessUrl("/")
        	.failureUrl("/login?error")
        	.usernameParameter("username").passwordParameter("password")
    	.and()
    	// Change logout
        	.logout()
        	.logoutUrl("/logout")
        	.logoutSuccessUrl("/login")
        .and()
	.csrf().disable();
    }

	
}
