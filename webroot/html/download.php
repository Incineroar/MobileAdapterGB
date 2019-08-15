<?php
    function test_input($data) {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data);
        return $data;
    }
    
    $valid = true;
    $file = "";
    
    if (isset($_GET["name"]))
    {
        if ($_GET["name"] == "")
        {
            $valid = false;
        }
        else
        {
            $file = test_input($_GET["name"]);
            $file = ltrim($file, '/');
        }
    }
    else
    {
        $valid = false;
    }
    
    if ($valid)
    {
        if (file_exists($file))
        {
            // If the file exists, serve it.
            header_remove(); // Headers are the devil.
            header("HTTP/1.0 200 OK");
            readfile($file); // This puts the file into the output buffer.
            exit; // Quit execution here, we're done!
        }
        else
        {
            // File not found, so 404!
            http_response_code(404);
            die();
        }
    }
    else
    {
        // Invalid string, so we'll just automatically 404. Ideally, a 400 would be better here but 404 is smarter
        http_response_code(404);
        die();
    }
?>