import { Routes, Route } from 'react-router-dom';
import { GroupList } from '@/pages/GroupList';
import { GroupDetail } from '@/pages/GroupDetail';
import { Layout } from '@/components/Layout';

function App() {
  return (
    <div className="relative z-10 min-h-full flex flex-col">
      <Layout>
        <Routes>
          <Route path="/" element={<GroupList />} />
          <Route path="/group/:path" element={<GroupDetail />} />
          <Route path="*" element={<GroupList />} />
        </Routes>
      </Layout>
    </div>
  );
}

export default App;
