<?php

/*Este login a diferencia este es mucho mas seguro, porque este esta usando la configuración de conexión PDO que se ajusta según tu entorno*/
/** Aca tenemos: */
//Cuando se usa desde una variable esto se puede cifrar o encapsular o proteger, asi es mucho mas dificil que un tercero ataque
//O bien esto se puede trabajar en otro archivo y se puede usar como cadena de conexión
$host = '127.0.0.1';
$db   = 'tienda';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';


//Aca realiza una cadena de conexión segura con PDO
//Este es mucho mejor usarlo desde una variable
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
/*Aca implementa los atributos o las configuraciones de PDO que mejoran la seguridad e implementan sentencias preparadas en SQL para evitar 
la inyección SQL*/
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // seguridad: usar prepared statements nativos
];
//Aca hay muchas mas lineas, pero la seguridad esta garantizada

//Aca se esta usando la cadena con PDO para establecer la conexión
try {
    $pdo = new PDO($dsn, $user, $pass, $options); // establezco la conexión con PDO ....
} catch (PDOException $e) {
    // En producción no mostrar detalles técnicos (previene fuga de información).
    exit('Error de conexión.');
}

//---BLOQUE LOGIN: este es el bloque de autenticacion, solo este bloque responde al intento de autenticación---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    //Seguridad: normalizar y validar entradas.
    //- El trim permite quitar espacios innecesarios que podrían confundir validaciones.
    //- Comprobar la existencia y evita usar índices no definidos.
    //- Usar trim tambien es una buena practica para utilizar los metodos POST
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        //Se omite cierta informacion tecnica, para que el usuario no sepa que estoy conectamdome o trabajando con la base de datos
        //Seguridad: no revelar cuál campo falta (evita dar información útil a atacantes).
        echo "Credenciales incompletas.";
        exit;
    }

    /* Seguridad aplicada: consulta preparada (Prepared Statement)
       ---------------------------------------------------------
       Razonamiento académico:
       Las sentencias preparadas separan la estructura SQL de los datos proporcionados
       por el usuario. Al usar parámetros vinculados (:username) evitamos que caracteres
       procedentes del input modifiquen la intención de la consulta SQL — esto mitiga
       directamente ataques de SQL Injection, que son una de las vulnerabilidades más
       comunes en autenticación basada en SQL. Además usamos LIMIT 1 para eficiencia. */
       //Aca se esta usando una sentencia que se llama: prepare. Desde PDO se utiliza prepare, para preparar la sentencia y encapsular el dato. Limitado a uno
       //Encapsula el dato dentro de una variable. primero esta con dos puntos y luego como variable, ahora la variable esta dentro del dato que esta reforzado


    $stmt = $pdo->prepare("SELECT id, username, password FROM usuarios WHERE username = :username LIMIT 1");
    $stmt->execute([':username' => $username]);
    $userRow = $stmt->fetch();

    /* Seguridad aplicada: almacenamiento de contraseñas con hash y verificación
       -----------------------------------------------------------------------
       Razonamiento académico:
       Nunca se deben comparar contraseñas en texto plano. En la tabla debe almacenarse
       el hash resultado de password_hash(). Para autenticar usamos password_verify(),
       que realiza la comparación segura entre el texto ingresado y el hash almacenado.
       Esto protege las credenciales incluso si la base de datos es comprometida. */

       /*Existe un metodo en PHP para verificar la password es mucho mejor que verificarlo que con:
         "if(mysqli_num_rows($resultado) > 0)" */

        //Protege las credenciales incluso si la base de datos es comprometida.
    if ($userRow && password_verify($password, $userRow['password'])) {
        // Seguridad: manejo de sesión
        // - session_start inicia la sesión.
        // - session_regenerate_id(true) evita fijación de sesión (session fixation).
        //Se maneja de mejor manera utilizando: session_start() para el manejo de sesiones 
        session_start();
        //Para evitar la fijación de la sesión
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userRow['id'];

        /* Seguridad aplicada: escape de salida para prevenir XSS al mostrar el nombre
           -------------------------------------------------------------------------
           Razonamiento académico:
           Cualquier dato que provenga de la base de datos o del input del usuario y se
           imprima en HTML debe ser escapado con htmlspecialchars o equivalente para evitar
           Cross-Site Scripting (XSS). Aunque aquí mostramos un mensaje simple, siempre
           escapamos la salida por principio de menor privilegio. */

           //Aca se aplica un principio que es escapar el codigo para prevenir el XSS, y se utiliza un metodo llamado htmlspecialchars
        $safeName = htmlspecialchars($userRow['username'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        echo "Bienvenido, $safeName";
    } else {
        /* Seguridad adicional recomendada (no implementada aquí por simplicidad):
           - Aplicar retardos o backoff progresivo tras intentos fallidos.
           - Contabilizar intentos y bloquear temporalmente la IP/usuario tras N fallos.
           - Registrar eventos de login fallidos en logs protegidos.
           Estas medidas reducen ataques de fuerza bruta y permiten auditoría. */
        echo "Acceso no autorizado.";
    }
    exit;
}
?>
