
USE TIENDA;

INSERT INTO roles (nombre) VALUES ("Administrador");

INSERT INTO usuarios (roles_id, email, password, nombres, apellidos, estado) 
       VALUES (1,'usuario01@tecsup.edu.pe','nose','usuario01','Tecsup',1 );

INSERT INTO roles (nombre) VALUES ("Ventas");

INSERT INTO usuarios (roles_id, email, password, nombres, apellidos, estado) 
       VALUES (2,'usuario02@tecsup.edu.pe','1234','usuario 02','Tecsup',1 );
              
       