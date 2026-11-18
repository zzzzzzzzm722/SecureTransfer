using SecureTransfer.Protocol;

namespace SecureTransfer.Client;
internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
public sealed class MainForm : Form
{
    private readonly TextBox host = new() { Text = "localhost" }, port = new() { Text = "7443" }, ca = new() { Text = Path.GetFullPath(".local/certs/ca.cer") }, user = new() { Text = "alice" }, password = new() { UseSystemPasswordChar = true };
    private readonly TextBox clientCert = new(), certPassword = new() { UseSystemPasswordChar = true };
    private readonly TextBox localFile = new() { Text = Path.GetFullPath(".local/upload/demo.bin") }, downloadDir = new() { Text = Path.GetFullPath(".local/downloads") };
    private readonly Button connect = new() { Text = "连接并登录", AutoSize = true }, refresh = new() { Text = "刷新列表", AutoSize = true }, upload = new() { Text = "上传文件", AutoSize = true }, download = new() { Text = "下载选中文件", AutoSize = true }, disconnect = new() { Text = "断开连接", AutoSize = true };
    private readonly ListView files = new() { View = View.Details, FullRowSelect = true, MultiSelect = false, Dock = DockStyle.Fill };
    private readonly TextBox log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    private readonly Label status = new() { Text = "未连接", AutoSize = true, Dock = DockStyle.Fill };
    private readonly ProgressBar progress = new() { Dock = DockStyle.Fill };
    private TransferClient? session;
    public MainForm()
    {
        Text = "安全文件传输 · 实验 1B";
        Width = 1180;
        Height = 1100;
        MinimumSize = new Size(1000, 1000);
        Font = new Font("Microsoft YaHei UI", 10);
        StartPosition = FormStartPosition.CenterScreen;
        var main = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(16) };
        main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
        main.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        main.RowStyles.Add(new RowStyle(SizeType.Absolute, 35));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
        var settings = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 9, AutoSize = true };
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 85));
        for (int i = 0; i < 9; i++)
            settings.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Add("服务器地址", host, 0);
        Add("端口", port, 1);
        Add("可信 CA 公证书", ca, 2, true);
        Add("账号", user, 3);
        Add("口令", password, 4);
        Add("客户端证书（可选）", clientCert, 5, true);
        Add("客户端证书口令", certPassword, 6);
        Add("本地上传文件", localFile, 7, true);
        Add("下载目录", downloadDir, 8, true);
        void Add(string label, TextBox box, int row, bool browse = false)
        {
            settings.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
            box.Dock = DockStyle.Fill;
            box.AccessibleName = label;
            settings.Controls.Add(box, 1, row);
            if (browse)
            {
                var b = new Button { Text = "浏览", Dock = DockStyle.Fill };
                b.Click += (_, _) =>
                {
                    if (row == 8)
                    {
                        using var folder = new FolderBrowserDialog();
                        if (folder.ShowDialog(this) == DialogResult.OK)
                            box.Text = folder.SelectedPath;
                        return;
                    }
                    using var dialog = new OpenFileDialog { Filter = row == 2 ? "CA 证书|*.cer;*.crt" : row == 5 ? "客户端证书|*.pfx" : "所有文件|*.*" };
                    if (dialog.ShowDialog(this) == DialogResult.OK)
                        box.Text = dialog.FileName;
                };
                settings.Controls.Add(b, 2, row);
            }
        }
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(0, 6, 0, 6) };
        actions.Controls.AddRange([connect, refresh, upload, download, disconnect]);
        files.Columns.Add("文件名", 620);
        files.Columns.Add("字节数", 200);
        main.Controls.Add(settings, 0, 0);
        main.Controls.Add(actions, 0, 1);
        main.Controls.Add(files, 0, 2);
        main.Controls.Add(progress, 0, 3);
        main.Controls.Add(status, 0, 4);
        main.Controls.Add(log, 0, 5);
        Controls.Add(main);
        connect.Click += async (_, _) => await Work(async () =>
        {
            if (session is not null)
                await session.DisposeAsync();
            session = new TransferClient();
            session.Status += message => { if (!IsDisposed && IsHandleCreated) BeginInvoke(() => { status.Text = message; Write(message); if (session?.Connected != true) SetButtons(false); }); };
            await session.ConnectAsync(host.Text.Trim(), int.Parse(port.Text), ca.Text.Trim(), user.Text.Trim(), password.Text, string.IsNullOrWhiteSpace(clientCert.Text) ? null : clientCert.Text, certPassword.Text);
            password.Clear();
            certPassword.Clear();
            await RefreshFiles();
        });
        refresh.Click += async (_, _) => await Work(RefreshFiles);
        upload.Click += async (_, _) =>
        {
            string path = localFile.Text.Trim();
            await Work(async () => { var result = await session!.UploadAsync(path, new Progress<int>(v => progress.Value = v)); Write($"上传成功：{Path.GetFileName(path)}，{result.Length} 字节，SHA-256 {result.Sha256}"); await RefreshFiles(); });
        };
        download.Click += async (_, _) =>
        {
            if (files.SelectedItems.Count == 0)
            {
                Write("请先选择远程文件。");
                return;
            }
            string name = files.SelectedItems[0].Text;
            string directory = downloadDir.Text.Trim();
            await Work(async () => { if (!Directory.Exists(directory)) throw new IOException("请先选择已存在的下载目录"); var result = await session!.DownloadAsync(name, directory, new Progress<int>(v => progress.Value = v)); Write($"下载成功：{name}，{result.Length} 字节，SHA-256 {result.Sha256}"); });
        };
        disconnect.Click += async (_, _) => { if (session is not null) await session.DisposeAsync(); session = null; status.Text = "已断开"; SetButtons(false); Write("连接已释放"); };
        FormClosed += (_, _) => session?.Abort();
        SetButtons(false);
    }
    private void Write(string text) => log.AppendText($"[{DateTime.Now:HH:mm:ss}] {text}{Environment.NewLine}");
    private void SetButtons(bool connected)
    {
        connect.Enabled = !connected;
        refresh.Enabled = upload.Enabled = download.Enabled = disconnect.Enabled = connected;
    }
    private async Task Work(Func<Task> action)
    {
        connect.Enabled = refresh.Enabled = upload.Enabled = download.Enabled = false;
        progress.Value = 0;
        try
        {
            await action();
        }
        catch (Exception ex) { Write("失败：" + ex.Message); status.Text = session?.Connected == true ? "操作失败，连接仍可用" : "连接已关闭，请重新登录"; }
        finally { SetButtons(session?.Connected == true); }
    }
    private async Task RefreshFiles()
    {
        var list = await session!.ListAsync();
        files.Items.Clear();
        foreach (var f in list)
            files.Items.Add(new ListViewItem([f.Name, f.Length.ToString()]));
        Write($"列表已刷新：{list.Length} 个文件；连接 {session.Session!.ConnectionId}");
    }
}
