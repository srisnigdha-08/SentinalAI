import Navbar from '../components/Navbar.jsx'
import Sidebar from '../components/Sidebar.jsx'
import RoleWorkspaceHeader from '../components/RoleWorkspaceHeader.jsx'

export default function DashboardLayout({ children }) {
  return (
    <>
      <Navbar />
      <div className="dashboard-shell" style={{ display: 'flex', paddingTop: 56, minHeight: '100vh' }}>
        <Sidebar />
        <main className="dashboard-main" style={{
          flex: 1, minWidth: 0, overflow: 'auto',
          background: '#020b18',
        }}>
          <RoleWorkspaceHeader />
          {children}
        </main>
      </div>
    </>
  )
}
