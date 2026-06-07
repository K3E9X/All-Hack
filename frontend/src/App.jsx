import { Outlet } from 'react-router-dom';
import TopNav from './components/TopNav.jsx';

export default function App() {
  return (
    <>
      <TopNav />
      <Outlet />
    </>
  );
}
