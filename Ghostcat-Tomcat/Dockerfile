FROM tomcat:8.0-jre8

# 1. Vulnerable webapp
RUN mkdir -p /usr/local/tomcat/webapps/ROOT/WEB-INF
RUN echo '<web-app>' > /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '  <display-name>Ghostcat Demo</display-name>' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '  <!-- DB_PASSWORD=Sup3rS3cr3t! -->' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '</web-app>' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml

# 2. Enable WebDAV writes in the ROOT context
RUN mkdir -p /usr/local/tomcat/conf/Catalina/localhost
RUN echo '<Context path="/" docBase="ROOT" privileged="true" antiResourceLocking="false" allowLinking="true">' \
         > /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml
RUN echo '  <Resources allowLinking="true" />' >> /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml
RUN echo '</Context>' >> /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

# 3. Replace the default web.xml with one that enables WebDAV (readonly=false)
RUN echo '<?xml version="1.0" encoding="UTF-8"?>' > /usr/local/tomcat/conf/web.xml
RUN echo '<web-app xmlns="http://java.sun.com/xml/ns/javaee"' >> /usr/local/tomcat/conf/web.xml
RUN echo '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' >> /usr/local/tomcat/conf/web.xml
RUN echo '         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee' >> /usr/local/tomcat/conf/web.xml
RUN echo '         http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"' >> /usr/local/tomcat/conf/web.xml
RUN echo '         version="3.0">' >> /usr/local/tomcat/conf/web.xml
RUN echo '' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <!-- Default servlet (needed for static content) -->' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <servlet>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-name>default</servlet-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-name>debug</param-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-value>0</param-value>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    </init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-name>listings</param-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-value>false</param-value>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    </init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <load-on-startup>1</load-on-startup>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  </servlet>' >> /usr/local/tomcat/conf/web.xml
RUN echo '' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <!-- WebDAV servlet (writable) -->' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <servlet>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-name>webdav</servlet-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-class>org.apache.catalina.servlets.WebdavServlet</servlet-class>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-name>debug</param-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-value>0</param-value>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    </init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-name>listings</param-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-value>true</param-value>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    </init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-name>readonly</param-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-value>false</param-value>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    </init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  </servlet>' >> /usr/local/tomcat/conf/web.xml
RUN echo '' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <!-- JSP servlet (needed to compile JSP) -->' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <servlet>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-name>jsp</servlet-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-name>fork</param-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-value>false</param-value>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    </init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-name>xpoweredBy</param-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '      <param-value>false</param-value>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    </init-param>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <load-on-startup>3</load-on-startup>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  </servlet>' >> /usr/local/tomcat/conf/web.xml
RUN echo '' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <!-- Mappings -->' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <servlet-mapping>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-name>default</servlet-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <url-pattern>/</url-pattern>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  </servlet-mapping>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <servlet-mapping>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-name>webdav</servlet-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <url-pattern>/webdav/*</url-pattern>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  </servlet-mapping>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  <servlet-mapping>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <servlet-name>jsp</servlet-name>' >> /usr/local/tomcat/conf/web.xml
RUN echo '    <url-pattern>*.jsp</url-pattern>' >> /usr/local/tomcat/conf/web.xml
RUN echo '  </servlet-mapping>' >> /usr/local/tomcat/conf/web.xml
RUN echo '</web-app>' >> /usr/local/tomcat/conf/web.xml
