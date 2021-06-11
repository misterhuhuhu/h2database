/*
 * Copyright 2004-2021 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.server;

import java.sql.SQLException;

/**
 * 实现这个接口的类通常提供一个
 * TCP/IP 侦听器，例如 FTP 服务器。
 * 可以启动和停止，可能会也可能不会
 * 允许远程连接。
 */
public interface Service {

    /**
     * 从命令行选项初始化服务。
     *
     * @param args the command line options
     */
    void init(String... args) throws Exception;

    /**
     * 以人类可读的形式获取此服务的 URL
     *
     * @return the url
     */
    String getURL();

    /**
     * 启动服务。 这通常意味着创建服务器套接字。
     * 此方法不能阻塞.
     */
    void start() throws SQLException;

    /**
     * 监听传入的连接。
     * 此方法阻塞。
     */
    void listen();

    /**
     * 停止服务。
     */
    void stop();

    /**
     * 检查服务是否正在运行。
     *
     * @param traceError if errors should be written
     * @return if the server is running
     */
    boolean isRunning(boolean traceError);

    /**
     * 检查是否允许远程连接。
     *
     * @return true if remote connections are allowed
     */
    boolean getAllowOthers();

    /**
     * 获取人类可读的服务名称。
     *
     * @return the name
     */
    String getName();

    /**
     * 获取人类可读的服务短名称。
     *
     * @return the type
     */
    String getType();

    /**
     * 获取此服务正在侦听的端口。
     *
     * @return the port
     */
    int getPort();

    /**
     * 检查是否应使用守护线程。
     *
     * @return true if a daemon thread should be used
     */
    boolean isDaemon();

}
