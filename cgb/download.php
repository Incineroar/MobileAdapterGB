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
            #check if the file exists, and if so, serve it.
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="'.basename($file).'"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($file));
            readfile($file);
            exit;
        }
        else
        {
            #else 404 not found.
            http_response_code(404);
            die();
        }
    }
    else
    {
        #page string isn't valid, we'll just 404 to cover our butts.
        http_response_code(404);
        die();
    }
?>