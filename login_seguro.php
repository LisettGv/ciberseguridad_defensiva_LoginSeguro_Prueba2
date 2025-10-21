<?php
// --- Configuración de conexión PDO (ajusta según tu entorno) ---
// Cifrar o encapsular .. o proteger, es mucho mas dificil que un tercero ataque.
// PDO SIGNIFICA: PHP Data Objects ... es una interfaz segura para nuestras conexiones..
// O puedo usar otro archivos y puedo utilizarlo como cadena de conexion.
// En este codigo hay mas lineas pero la seguridada esta garantizada.

$host = '127.0.0.1';
$db   = 'tienda';
$user = 'root';
$pass = '';

$charset = 'utf8mb4';
$dsn = "mysql:host=$host;dbname=$db;charset=$charset"; /** dbname-$db desde una variable */

/** Implementacion de los atributos configuraciones de PDO mejoran la seguridad e implementan 
 * sentencias preparadas en SQL para evitar la penetracion del SQL injection */
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // seguridad: usar prepared statements nativos
];

/** Aca se esta utilizando la cadena con PDO, para establecer la conexión.... Se esta implementado 
 * la conexión segura con exito */
try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    // En producción no mostrar detalles técnicos (previene fuga de información).
    exit('Error de conexión.');
}

// --- BLOQUE LOGIN: solo este bloque responde al intento de autenticación ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Seguridad: normalizar y validar entradas.
    // - TRIM: quita espacios innecesarios que podrían confundir validaciones.
    // Usar trim es una buena práctica para los metodos POST.
    // - Comprobar existencia evita usar índices no definidos.
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        // Seguridad: no revelar cuál campo falta (evita dar información útil a atacantes).
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
    $stmt = $pdo->prepare("SELECT id, username, password FROM usuarios 
    WHERE username = :username LIMIT 1");
    $stmt->execute([':username' => $username]);
    $userRow = $stmt->fetch();

    /* Seguridad aplicada: almacenamiento de contraseñas con hash y verificación
       -----------------------------------------------------------------------
       Razonamiento académico:
       Nunca se deben comparar contraseñas en texto plano. En la tabla debe almacenarse
       el hash resultado de password_hash(). Para autenticar usamos password_verify(),
       que realiza la comparación segura entre el texto ingresado y el hash almacenado.
       Esto protege las credenciales incluso si la base de datos es comprometida. */
    if ($userRow && password_verify($password, $userRow['password'])) {
        // Seguridad: manejo de sesión
        // - session_start inicia la sesión.
        // - session_regenerate_id(true) evita fijación de sesión (session fixation).
        session_start();
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userRow['id'];

        /* Seguridad aplicada: escape de salida para prevenir XSS al mostrar el nombre
           -------------------------------------------------------------------------
           Razonamiento académico:
           Cualquier dato que provenga de la base de datos o del input del usuario y se
           imprima en HTML debe ser escapado con htmlspecialchars o equivalente para evitar
           Cross-Site Scripting (XSS). Aunque aquí mostramos un mensaje simple, siempre
           escapamos la salida por principio de menor privilegio. */
        $safeName = htmlspecialchars($userRow['username'], ENT_QUOTES | 
        ENT_SUBSTITUTE, 'UTF-8');
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
