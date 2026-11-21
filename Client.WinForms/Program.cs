using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureTransfer.Protocol;

namespace SecureTransfer.Client;
internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        GuiProfile? profile = null;
        if (args.Length == 2 && args[0] == "--profile") profile = JsonSerializer.Deserialize<GuiProfile>(File.ReadAllText(args[1]));
        Application.Run(new MainForm(profile));
    }
}
public sealed record GuiProfile(string Host, int Port, string Ca, string User, string Certificate,
    string UploadFiles, string DownloadDirectory, string StateRoot);

public sealed class MainForm : Form
{
    private readonly TextBox host = new() { Text = "localhost" }, port = new() { Text = "7443" }, ca = new() { Text = Path.GetFullPath(".local/certs/ca.cer") };
    private readonly TextBox user = new() { Text = "alice" }, password = new() { UseSystemPasswordChar = true };
    private readonly TextBox clientCert = new() { Text = Path.GetFullPath(".local/certs/alice.pfx") }, certPassword = new() { UseSystemPasswordChar = true };
    private readonly TextBox localFiles = new() { Multiline = true, Height = 60, ScrollBars = ScrollBars.Vertical };
    private readonly TextBox downloadDir = new() { Text = Path.GetFullPath(".local/downloads") }, stateRoot = new() { Text = Path.GetFullPath(".local/client-state") };
    private readonly Button connect = new() { Text = "连接并登录", AutoSize = true }, refresh = new() { Text = "刷新列表", AutoSize = true }, upload = new() { Text = "并行上传", AutoSize = true }, download = new() { Text = "并行下载选中文件", AutoSize = true }, disconnect = new() { Text = "断开连接", AutoSize = true };
    private readonly Button cancel = new() { Text = "取消选中任务", AutoSize = true }, resume = new() { Text = "恢复选中任务", AutoSize = true };
    private readonly ListView files = new() { View = View.Details, FullRowSelect = true, MultiSelect = true, Dock = DockStyle.Fill, AccessibleName = "远程文件列表" };
    private readonly ListView tasks = new() { View = View.Details, FullRowSelect = true, MultiSelect = true, ShowItemToolTips = true, Dock = DockStyle.Fill, AccessibleName = "传输任务列表" };
    private readonly TextBox log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, AccessibleName = "操作日志" };
    private readonly Label status = new() { Text = "未连接；默认要求双向证书", AutoSize = true, Dock = DockStyle.Fill };
    private readonly Dictionary<string, ListViewItem> rows = [];
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 1000 };
    private TransferPool? pool;
    private TransferWorkspace? workspace;
    private CancellationTokenSource? connectCancellation;
    private Task<TransferPool>? connecting;
    private Task? disconnecting;
    private int generation;
    private bool closing, closeReady;

    public MainForm(GuiProfile? profile = null)
    {
        Text = "安全文件传输 · 并行与断点续传"; Width = 1420; Height = 1320; MinimumSize = new Size(1180, 1100);
        Font = new Font("Microsoft YaHei UI", 10); StartPosition = FormStartPosition.CenterScreen;
        if (profile is not null)
        {
            host.Text = profile.Host; port.Text = profile.Port.ToString(); ca.Text = profile.Ca; user.Text = profile.User;
            clientCert.Text = profile.Certificate; localFiles.Text = profile.UploadFiles; downloadDir.Text = profile.DownloadDirectory; stateRoot.Text = profile.StateRoot;
        }
        var main = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 8, Padding = new Padding(12) };
        main.RowStyles.Add(new RowStyle(SizeType.AutoSize)); main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 25)); main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 45)); main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 30)); main.RowStyles.Add(new RowStyle(SizeType.Absolute, 4));
        var settings = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3, RowCount = 10 };
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); settings.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 85));
        var fields = new[] { ("服务器地址",host), ("端口",port), ("可信 CA 公证书",ca), ("账号",user), ("口令",password), ("客户端证书（必填）",clientCert), ("客户端证书口令",certPassword), ("本地文件（每行一个）",localFiles), ("下载目录",downloadDir), ("本地恢复目录",stateRoot) };
        for (int index = 0; index < fields.Length; index++)
        {
            int row = index; var (label, box) = fields[row]; settings.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            settings.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
            box.Dock = DockStyle.Fill; box.AccessibleName = label; settings.Controls.Add(box, 1, row);
            if (row is 2 or 5 or 7 or 8 or 9)
            {
                var browse = new Button { Text = "浏览", Dock = DockStyle.Fill };
                browse.Click += (_, _) =>
                {
                    if (row >= 8) { using var dialog = new FolderBrowserDialog(); if (dialog.ShowDialog(this) == DialogResult.OK) box.Text = dialog.SelectedPath; }
                    else { using var dialog = new OpenFileDialog { Multiselect = row == 7, Filter = row == 2 ? "CA 证书|*.cer;*.crt" : row == 5 ? "客户端证书|*.pfx" : "所有文件|*.*" }; if (dialog.ShowDialog(this) == DialogResult.OK) box.Text = string.Join(Environment.NewLine, dialog.FileNames); }
                };
                settings.Controls.Add(browse, 2, row);
            }
        }
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true }; actions.Controls.AddRange([connect, refresh, upload, download, disconnect]);
        var taskActions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true }; taskActions.Controls.AddRange([cancel, resume, new Label { Text = "最多 3 条长连接；取消保留已确认断点", AutoSize = true }]);
        files.Columns.Add("远程文件（可多选）", 750); files.Columns.Add("字节数", 250);
        foreach (var (name,width) in new[] { ("任务文件",190), ("方向",80), ("状态",220), ("已确认/总字节",340), ("恢复偏移",150), ("连接 / 错误",250) }) tasks.Columns.Add(name,width);
        main.Controls.Add(settings,0,0); main.Controls.Add(actions,0,1); main.Controls.Add(files,0,2); main.Controls.Add(taskActions,0,3);
        main.Controls.Add(tasks,0,4); main.Controls.Add(status,0,5); main.Controls.Add(log,0,6); Controls.Add(main);
        connect.Click += async (_,_) => await UiAction(Connect);
        refresh.Click += async (_,_) => await UiAction(RefreshFiles);
        disconnect.Click += async (_,_) => await UiAction(Disconnect);
        upload.Click += (_,_) => AddUploads(); download.Click += (_,_) => AddDownloads();
        cancel.Click += (_,_) => { foreach (ListViewItem item in tasks.SelectedItems) if (item.Tag is TransferJob job) workspace?.Cancel(job); };
        resume.Click += (_,_) => { var current = workspace; if (current is null) return; foreach (ListViewItem item in tasks.SelectedItems) if (item.Tag is TransferJob job && job.Completion.IsCompleted && job.State != "已完成") _ = current.Start(job); };
        FormClosing += async (_, e) =>
        {
            if (closeReady) return;
            e.Cancel = true; if (closing) return; closing = true; timer.Stop();
            await UiAction(Disconnect); closeReady = true; Close();
        };
        FormClosed += (_,_) => timer.Dispose();
        timer.Tick += (_,_) => RefreshConnectionState();
        timer.Start(); UpdateButtons();
    }
    private async Task UiAction(Func<Task> action) { try { await action(); } catch (Exception ex) { Write("失败：" + ex.Message); } finally { if (!IsDisposed) UpdateButtons(); } }
    private void Write(string message)
    {
        if (log.TextLength > 24000) log.Text = log.Text[^12000..];
        log.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
    }
    private void Post(Action action)
    {
        if (IsDisposed || Disposing || !IsHandleCreated) return;
        try { BeginInvoke(() => { if (!IsDisposed && !Disposing && !closing) action(); }); } catch (InvalidOperationException) { }
    }
    private void UpdateButtons()
    {
        bool busy = connecting is { IsCompleted:false } || disconnecting is { IsCompleted:false };
        bool open = pool is { IsOpen:true } && !busy && !closing;
        bool healthy = open && pool!.ConnectedCount > 0;
        connect.Enabled = !healthy && !busy && !closing; refresh.Enabled = upload.Enabled = download.Enabled = healthy;
        cancel.Enabled = resume.Enabled = open; disconnect.Enabled = (open || connecting is { IsCompleted:false }) && !closing;
        foreach (var box in new[] { host, port, ca, user, password, clientCert, certPassword, stateRoot }) box.Enabled = !healthy && !busy && !closing;
    }
    private void RefreshConnectionState()
    {
        if (pool is { IsOpen:true } current)
            status.Text = current.ConnectedCount == 0 ? "连接已失效；请重新登录后恢复任务" : $"已认证长连接 {current.ConnectedCount}/3；活动任务 {workspace?.Jobs.Count(j=>!j.Completion.IsCompleted) ?? 0}；中断后可恢复";
        UpdateButtons();
    }
    private async Task Connect()
    {
        if (connecting is { IsCompleted:false }) return;
        await Disconnect();
        if (!File.Exists(clientCert.Text.Trim())) throw new IOException("请选择账号对应的客户端 PFX 证书");
        int epoch = ++generation;
        var settings = new ConnectionSettings(host.Text.Trim(), int.Parse(port.Text), ca.Text.Trim(), user.Text.Trim(), password.Text, clientCert.Text.Trim(), certPassword.Text);
        connectCancellation = new CancellationTokenSource();
        connecting = TransferPool.ConnectAsync(settings, connectCancellation.Token); UpdateButtons();
        var connected = await connecting;
        if (epoch != generation || closing) { await connected.DisposeAsync(); return; }
        pool = connected;
        connected.ConnectionChanged += () => Post(() => { if (epoch == generation && ReferenceEquals(pool, connected)) RefreshConnectionState(); });
        string key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{settings.Host}:{settings.Port}/{settings.User}")))[..16];
        var current = new TransferWorkspace(connected, Path.Combine(stateRoot.Text.Trim(), key)); workspace = current;
        current.Changed += job => Post(() => { if (generation == epoch && ReferenceEquals(workspace, current)) UpdateJob(job); });
        rows.Clear(); tasks.Items.Clear(); foreach (var job in current.Jobs) UpdateJob(job);
        password.Clear(); certPassword.Clear();
        Write("双向认证成功；连接池 ID：" + string.Join(", ", connected.ConnectionIds)); await RefreshFiles(); UpdateButtons();
    }
    private Task Disconnect()
    {
        if (disconnecting is { IsCompleted:false }) return disconnecting;
        return disconnecting = DisconnectCore();
    }
    private async Task DisconnectCore()
    {
        generation++; connectCancellation?.Cancel();
        var oldWorkspace = workspace; var oldPool = pool; workspace = null; pool = null; UpdateButtons();
        if (oldWorkspace is not null) await oldWorkspace.DisposeAsync(); else if (oldPool is not null) await oldPool.DisposeAsync();
        if (connecting is not null) { try { var arrived = await connecting; await arrived.DisposeAsync(); } catch { } connecting = null; }
        connectCancellation?.Dispose(); connectCancellation = null;
        status.Text = "已断开；断点已保留，重新登录后可恢复"; Write("连接已释放；已确认的数据可续传");
        if (oldWorkspace is not null) foreach (var job in oldWorkspace.Jobs) UpdateJob(job);
    }
    private async Task RefreshFiles()
    {
        var current = pool ?? throw new IOException("未连接"); int epoch = generation;
        var list = await current.ListAsync();
        if (epoch != generation) return;
        files.Items.Clear(); foreach (var file in list) files.Items.Add(new ListViewItem([file.Name,file.Length.ToString()]));
        Write($"远程文件 {list.Length} 个；当前长连接 {current.ConnectedCount}");
    }
    private void AddUploads()
    {
        try
        {
            var current = workspace ?? throw new IOException("未连接");
            var paths = localFiles.Lines.Select(p=>p.Trim().Trim('"')).Where(p=>p.Length>0).Distinct().ToArray();
            if (paths.Length == 0) throw new IOException("请选择一个或多个本地文件");
            foreach (string path in paths) { var job = current.Add("upload",Path.GetFullPath(path)); UpdateJob(job); _ = current.Start(job); }
        }
        catch (Exception ex) { Write("失败："+ex.Message); }
    }
    private void AddDownloads()
    {
        try
        {
            var current = workspace ?? throw new IOException("未连接");
            if (files.SelectedItems.Count == 0) throw new IOException("请多选一个或多个远程文件");
            foreach (ListViewItem item in files.SelectedItems) { var job=current.Add("download",item.Text,Path.GetFullPath(downloadDir.Text.Trim())); UpdateJob(job); _=current.Start(job); }
        }
        catch (Exception ex) { Write("失败："+ex.Message); }
    }
    private void UpdateJob(TransferJob job)
    {
        if (!rows.TryGetValue(job.Plan.Id,out var row)) { row=new ListViewItem(new string[6]); row.Tag=job; rows[job.Plan.Id]=row; tasks.Items.Add(row); }
        var p=job.Progress; row.SubItems[0].Text=Path.GetFileName(job.Plan.Source); row.SubItems[1].Text=job.Plan.Direction=="upload"?"上传":"下载";
        row.SubItems[2].Text=job.State; row.SubItems[3].Text=p is null?"0":$"{p.Bytes}/{p.Total} ({p.Percent}%)"; row.SubItems[4].Text=p?.ResumedFrom.ToString()??"0";
        row.SubItems[5].Text=job.Error??p?.ConnectionId??"";
        row.ToolTipText=$"{job.Plan.Source}\n{job.State}\n{row.SubItems[3].Text}\n恢复偏移：{row.SubItems[4].Text}\n{job.Error??job.Result?.Sha256??row.SubItems[5].Text}";
        if (job.Completion.IsCompleted || job.Result is not null || job.Error is not null)
            Write($"{Path.GetFileName(job.Plan.Source)}：{job.State} {job.Error ?? job.Result?.Sha256}");
    }
}
