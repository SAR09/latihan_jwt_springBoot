package programmermuda.spring.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import programmermuda.spring.jwt.config.RSAKeyRecord;

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class ProgrammeermudaProjectJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProgrammeermudaProjectJwtApplication.class, args);
	}

}
