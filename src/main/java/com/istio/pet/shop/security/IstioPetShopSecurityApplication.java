package com.istio.pet.shop.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
Endpoints disponibilizados pela biblioteca de saúde da aplicação: spring-boot-starter-actuator

http://localhost:8080/pet-shop/actuator/health

Essa url pode ser utilizado pelo kubernetes para verificar a saúde da aplicação.

/auditevents – lists security audit-related events such as user login/logout. Also, we can filter by principal or type among other fields
/beans – returns all available beans in our BeanFactory. Unlike /auditevents, it doesn't support filtering
/conditions – formerly known as /autoconfig, builds a report of conditions around auto-configuration
/configprops – allows us to fetch all @ConfigurationProperties beans
/env – returns the current environment properties. Additionally, we can retrieve single properties
/flyway – provides details about our Flyway database migrations
/health – summarises the health status of our application
/heapdump – builds and returns a heap dump from the JVM used by our application
/info – returns general information. It might be custom data, build information or details about the latest commit
/liquibase – behaves like /flyway but for Liquibase
/logfile – returns ordinary application logs
/loggers – enables us to query and modify the logging level of our application
/metrics – details metrics of our application. This might include generic metrics as well as custom ones
/prometheus – returns metrics like the previous one, but formatted to work with a Prometheus server
/scheduledtasks – provides details about every scheduled task within our application
/sessions – lists HTTP sessions given we are using Spring Session
/shutdown – performs a graceful shutdown of the application
/threaddump – dumps the thread information of the underlying JVM
 * @author breno
 *
 */

@SpringBootApplication
public class IstioPetShopSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(IstioPetShopSecurityApplication.class, args);
	}

}
